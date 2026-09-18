package acceptance_test

// Private research increment: protocol driver only. A native public-ACS runner
// must supply independently validated trampoline phase/settlement receipts.
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const devinSeat = "/exa.seat_management_pb.SeatManagementService/"
const devinAnalytics = "/exa.product_analytics_pb.ProductAnalyticsService/BatchRecordAnalyticsEvents"
const devinModel = "/exa.api_server_pb.ApiServerService/GetChatMessage"

type devinWireField struct {
	tag    uint64
	wire   byte
	number uint64
	data   []byte
}

func devinWire(b []byte) ([]devinWireField, error) {
	if len(b) > 1<<20 {
		return nil, errors.New("protobuf byte cap")
	}
	var out []devinWireField
	for len(b) > 0 {
		if len(out) >= 8192 {
			return nil, errors.New("protobuf field cap")
		}
		key, n := binary.Uvarint(b)
		if n <= 0 || key>>3 == 0 || key>>3 > 536870911 {
			return nil, errors.New("invalid protobuf key")
		}
		b = b[n:]
		f := devinWireField{tag: key >> 3, wire: byte(key & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("invalid varint")
			}
			f.number = v
			b = b[n:]
		case 1, 5:
			size := 8
			if f.wire == 5 {
				size = 4
			}
			if len(b) < size {
				return nil, io.ErrUnexpectedEOF
			}
			f.data = b[:size]
			b = b[size:]
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 || size > uint64(len(b)-n) {
				return nil, io.ErrUnexpectedEOF
			}
			b = b[n:]
			f.data = b[:int(size)]
			b = b[int(size):]
		default:
			return nil, errors.New("unsupported protobuf wire")
		}
		out = append(out, f)
	}
	return out, nil
}
func devinOne(fields []devinWireField, tag uint64, wire byte) (devinWireField, error) {
	var found devinWireField
	count := 0
	for _, f := range fields {
		if f.tag == tag {
			if f.wire != wire {
				return found, errors.New("unexpected field wire")
			}
			found = f
			count++
		}
	}
	if count != 1 {
		return found, fmt.Errorf("field %d count %d", tag, count)
	}
	return found, nil
}
func devinFrame(payload []byte) []byte {
	b := make([]byte, 5, len(payload)+12)
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	b = append(b, payload...)
	return append(b, 2, 0, 0, 0, 2, '{', '}')
}
func devinBytes(tag byte, b []byte) []byte {
	out := []byte{tag<<3 | 2}
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func devinCall(id, name, args string) []byte {
	nested := append(devinBytes(1, []byte(id)), devinBytes(2, []byte(name))...)
	nested = append(nested, devinBytes(3, []byte(args))...)
	return devinFrame(append([]byte{0x28, 10}, devinBytes(6, nested)...))
}
func devinResult(body []byte, id string) (string, error) {
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		return "", errors.New("expected one uncompressed Connect frame")
	}
	fields, err := devinWire(body[5:])
	if err != nil {
		return "", err
	}
	found := ""
	count := 0
	for _, f := range fields {
		if f.tag != 3 {
			continue
		}
		if f.wire != 2 {
			return "", errors.New("message wire")
		}
		m, e := devinWire(f.data)
		if e != nil {
			return "", e
		}
		var ids []devinWireField
		for _, v := range m {
			if v.tag == 7 {
				ids = append(ids, v)
			}
		}
		for _, v := range ids {
			if v.wire != 2 {
				return "", errors.New("call ID wire")
			}
			if string(v.data) != id {
				continue
			}
			if len(ids) != 1 {
				return "", errors.New("duplicate call ID field")
			}
			role, e := devinOne(m, 2, 0)
			if e != nil || role.number != 4 {
				return "", errors.New("matched ID is not tool role4")
			}
			text, e := devinOne(m, 3, 2)
			if e != nil || !utf8.Valid(text.data) || len(text.data) > 65536 {
				return "", errors.New("invalid tool result")
			}
			found = string(text.data)
			count++
		}
	}
	if count != 1 {
		return "", fmt.Errorf("matched tool results %d", count)
	}
	return found, nil
}

type devinPhaseReceipt struct {
	PID                       int
	Argv                      []string
	MemberSHA256, SessionHome string
}

type devinPhaseStartedReceipt struct {
	PID, Parent int
	Argv        []string
}

type devinPhaseDoneReceipt struct {
	PID, Parent, ExitCode int
	Forced                bool
}

// devinPhaseCompletionDiagnostic classifies the completion gate without
// emitting receipt contents, argv, paths, or environment values.
func devinPhaseCompletionDiagnostic(phase string, readyPID int, started devinPhaseStartedReceipt, done devinPhaseDoneReceipt, expected []string) string {
	label := "unknown"
	if phase == "skills" || phase == "auth" || phase == "attached" {
		label = phase
	}
	ready := readyPID > 1
	startedParent := started.Parent == readyPID
	doneParent := done.Parent == readyPID
	startedPID := started.PID > 1
	donePID := done.PID > 1
	pidMatch := started.PID == done.PID
	exitZero := done.ExitCode == 0
	argv := reflect.DeepEqual(started.Argv, expected)
	phaseKnown := label != "unknown"
	if ready && startedParent && doneParent && startedPID && donePID && pidMatch && !done.Forced && exitZero && argv && phaseKnown {
		return ""
	}
	return fmt.Sprintf("phase=%s ready=%t started-parent=%t done-parent=%t started-pid=%t done-pid=%t pid-match=%t forced=%t exit-code=%d exit-zero=%t argv=%t phase-known=%t", label, ready, startedParent, doneParent, startedPID, donePID, pidMatch, done.Forced, done.ExitCode, exitZero, argv, phaseKnown)
}

type devinHTTPReceipt struct {
	Phase, Path, Method                              string
	Bytes, Status                                    int
	Complete                                         bool
	BodyComplete, ReplyComplete, AncillaryDisconnect bool
	Body                                             []byte
	ContentType, ResponseContentType, ReplyError     string
	ResponseBytes, WrittenBytes                      int
}
type devinDriver struct {
	mu                                                                  sync.Mutex
	member, home                                                        string
	phase                                                               string
	generation, requests, totalBytes, team, models, modelWrites, active int
	ended                                                               bool
	submissionRequired, submitAuthorized                                bool
	guardedExit                                                         bool
	ancillaryDisconnects                                                int
	failure                                                             error
	receipts                                                            []devinHTTPReceipt
	// Host-observed immutable server journal/effect checks. Required on every
	// model continuation, never inferred from assistant text or a timer.
	serverProof func(stage int) error
	// The native harness must validate the complete observed listing format.
	// No default substring heuristic: unknown formats fail closed.
	listingProof func(stage int, correlatedResult string) error
}

func (d *devinDriver) begin(r devinPhaseReceipt) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return d.failure
	}
	if r.PID <= 1 || r.MemberSHA256 != d.member || r.SessionHome != d.home {
		return errors.New("unvalidated phase identity")
	}
	phases := [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}}
	if d.generation >= len(phases) || !reflect.DeepEqual(r.Argv, phases[d.generation]) || d.active != 0 || (d.generation > 0 && !d.ended) {
		return errors.New("phase sequence or prior settlement")
	}
	d.phase = []string{"skills", "auth", "attached"}[d.generation]
	d.generation++
	d.team = 0
	d.requests = 0
	d.ended = false
	return nil
}
func (d *devinDriver) end(natural bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !natural || d.active != 0 || d.ended || d.generation == 0 {
		return errors.New("phase not settled")
	}
	d.ended = true
	return nil
}
func (d *devinDriver) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure == nil {
		d.failure = err
	}
}
func (d *devinDriver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := devinRequestMetadata(r); err != nil {
		d.fail(err)
		http.Error(w, "secret serialization", 409)
		return
	}

	d.mu.Lock()
	if d.failure != nil || d.phase == "" || d.ended {
		d.mu.Unlock()
		http.Error(w, "fixture phase unavailable", 409)
		return
	}
	phase := d.phase
	d.requests++
	limit := 16
	if phase == "attached" {
		limit = 32
	}
	d.active++
	index := len(d.receipts)
	d.receipts = append(d.receipts, devinHTTPReceipt{Phase: phase, Path: r.URL.Path, Method: r.Method})
	over := d.requests > limit
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.active--; d.mu.Unlock() }()
	if over {
		d.fail(errors.New("phase HTTP request cap"))
		http.Error(w, "request cap", 429)
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.ContentLength < 0 || r.ContentLength > 1<<20 || len(r.TransferEncoding) > 0 {
		d.fail(errors.New("HTTP method/framing refusal"))
		http.Error(w, "framing refusal", 400)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || int64(len(body)) != r.ContentLength {
		d.fail(errors.New("incomplete HTTP body"))
		http.Error(w, "body refusal", 400)
		return
	}
	if err := devinRejectSecret(body); err != nil {
		d.fail(err)
		http.Error(w, "secret serialization", 409)
		return
	}
	d.mu.Lock()
	d.totalBytes += len(body)
	d.receipts[index].Bytes = len(body)
	d.receipts[index].BodyComplete = true
	d.receipts[index].Body = append([]byte(nil), body...)
	d.receipts[index].ContentType = r.Header.Get("Content-Type")
	over = d.totalBytes > 2<<20
	d.mu.Unlock()
	if over {
		d.fail(errors.New("aggregate HTTP cap"))
		http.Error(w, "aggregate cap", 429)
		return
	}
	status := 501
	content := "application/json"
	data := []byte(`{"code":"unimplemented","message":"ACS synthetic local driver"}`)
	switch r.URL.Path {
	case devinSeat + "GetCliTeamSettings":
		if r.Header.Get("Content-Type") != "application/proto" {
			d.fail(errors.New("team content type"))
			http.Error(w, "type", 400)
			return
		}
		d.mu.Lock()
		d.team++
		n := d.team
		d.mu.Unlock()
		if n <= 2 {
			status = 200
			content = "application/proto"
			data = []byte{8, 1}
		}
	case devinModel:
		if phase != "attached" || r.Header.Get("Content-Type") != "application/connect+proto" {
			d.fail(errors.New("model outside attached phase or wrong type"))
			http.Error(w, "model refused", 403)
			return
		}
		d.mu.Lock()
		if d.models != d.modelWrites {
			d.mu.Unlock()
			d.fail(errors.New("overlapping model request"))
			http.Error(w, "ordering", 409)
			return
		}
		if d.submissionRequired && !d.submitAuthorized {
			d.mu.Unlock()
			d.fail(errors.New("model before completed Enter"))
			http.Error(w, "submission", 409)
			return
		}
		d.models++
		n := d.models
		d.mu.Unlock()
		if n > 4 {
			d.fail(errors.New("model turn cap"))
			http.Error(w, "model cap", 429)
			return
		}
		if n == 1 {
			if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
				d.fail(errors.New("initial Connect framing"))
				http.Error(w, "framing", 400)
				return
			}
			if _, err = devinWire(body[5:]); err != nil {
				d.fail(err)
				http.Error(w, "protobuf", 400)
				return
			}
		}
		if n > 1 {
			id := []string{"acs-list-servers-1", "acs-list-tools-1", "acs-call-1"}[n-2]
			result, e := devinResult(body, id)
			if e != nil {
				d.fail(e)
				http.Error(w, "correlation", 400)
				return
			}
			if d.serverProof == nil || (n < 4 && d.listingProof == nil) {
				d.fail(errors.New("independent proof validator absent"))
				http.Error(w, "proof", 409)
				return
			}
			if n < 4 {
				e = d.listingProof(n-1, result)
			} else if result != "ACS_MCP_TOOL_OK" {
				e = errors.New("unexpected correlated effect result")
			}
			if e != nil {
				d.fail(e)
				http.Error(w, "result proof", 409)
				return
			}

			if e = d.serverProof(n - 1); e != nil {
				d.fail(e)
				http.Error(w, "server proof", 409)
				return
			}
		}
		status = 200
		content = "application/connect+proto"
		switch n {
		case 1:
			data = devinCall("acs-list-servers-1", "mcp_list_servers", "{}")
		case 2:
			data = devinCall("acs-list-tools-1", "mcp_list_tools", `{"server_name":"fixture"}`)
		case 3:
			data = devinCall("acs-call-1", "mcp_call_tool", `{"server_name":"fixture","tool_name":"acs_allowed_echo","arguments":{}}`)
		case 4:
			data = devinFrame(devinBytes(3, []byte("READY")))
		}
	}
	w.Header().Set("Content-Type", content)
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.WriteHeader(status)
	written, err := w.Write(data)
	d.mu.Lock()
	d.receipts[index].Status = status
	receipt := &d.receipts[index]
	receipt.ResponseContentType = content
	receipt.ResponseBytes = len(data)
	receipt.WrittenBytes = written
	receipt.ReplyComplete = err == nil && written == len(data)
	receipt.Complete = receipt.BodyComplete && receipt.ReplyComplete
	if err != nil {
		receipt.ReplyError = "write-failure"
		if errors.Is(err, syscall.EPIPE) {
			receipt.ReplyError = "broken-pipe"
		}
	}
	if receipt.Complete && r.URL.Path == devinModel && status == 200 {
		d.modelWrites++
	}
	if !receipt.ReplyComplete {
		allowed := d.guardedExit && phase == "attached" && r.URL.Path == devinAnalytics && r.Method == "POST" && r.Header.Get("Content-Type") == "application/proto" && receipt.BodyComplete && len(receipt.Body) == receipt.Bytes && status == 501 && content == "application/json" && string(data) == `{"code":"unimplemented","message":"ACS synthetic local driver"}` && errors.Is(err, syscall.EPIPE) && d.ancillaryDisconnects < 2
		if allowed {
			receipt.AncillaryDisconnect = true
			d.ancillaryDisconnects++
		} else if d.failure == nil {
			d.failure = errors.New("incomplete response write")
		}
	}

	d.mu.Unlock()
}

// startDevinListener binds the credential's saved loopback endpoint exactly.
// It does not assert that ACS implements an egress firewall.
func startDevinListener(d *devinDriver, address string) (func() error, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return nil, errors.New("non-loopback driver endpoint")
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: d, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdown := server.Shutdown(ctx)
		if shutdown != nil {
			_ = server.Close()
			d.fail(errors.New("HTTP server forced close"))
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-ctx.Done():
			return errors.New("HTTP serve settlement deadline")
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if shutdown != nil {
			return shutdown
		}
		if d.active != 0 {
			return errors.New("active HTTP handlers after shutdown")
		}
		return d.failure
	}, nil
}

// Hold the same mutex as model acceptance across the bounded terminal write.
// Concurrent model arrivals cannot cross a failed or incomplete Enter write.
func (d *devinDriver) submitInput(write func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.submissionRequired || d.submitAuthorized || d.models != 0 || d.failure != nil {
		return errors.New("invalid submission boundary")
	}
	if e := write(); e != nil {
		d.failure = e
		return e
	}
	d.submitAuthorized = true
	return nil
}

// This is entered only at the observed empty successful idle, immediately before
// the one documented exit byte. It does not forgive a failed terminal write.
func (d *devinDriver) markGuardedExit() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil || d.guardedExit || !d.submissionRequired || !d.submitAuthorized || d.phase != "attached" || d.generation != 3 || d.ended || d.models != 4 || d.modelWrites != 4 {
		return errors.New("exit before completed native conversation")
	}
	completedModels := 0
	for _, r := range d.receipts {
		if r.Path == devinModel {
			completedModels++
			if r.Phase != "attached" {
				return errors.New("model receipt outside attached exit phase")
			}
		}
		if r.Path == devinModel && (!r.BodyComplete || !r.ReplyComplete || r.Status != 200) {
			return errors.New("exit with incomplete model receipt")
		}
	}
	if completedModels != 4 {
		return errors.New("exit missing four model receipts")
	}
	d.guardedExit = true
	return nil
}
