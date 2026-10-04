package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

type signalRecoveryRepository struct{ cli.ProfileRepository }

func (signalRecoveryRepository) Recover(ctx context.Context) (profilerepo.Outcome, error) {
	// Readiness proves the actual early executable dispatch installed its signal
	// context before either termination signal is delivered to this process.
	println("recovery ready")
	<-ctx.Done()
	return profilerepo.Outcome{State: profilerepo.NotCommitted}, ctx.Err()
}
func TestExecutableProfileRecoverySignalHelper(t *testing.T) {
	if os.Getenv("ACS_RECOVERY_SIGNAL_HELPER") != "1" {
		return
	}
	app := cli.App{Repository: signalRecoveryRepository{}, Output: os.Stdout, ErrorOutput: os.Stderr}
	handled, code := runProfileRecovery(app, []string{"profile", "recover", "--json"}, func() (string, error) { panic("injected recovery discovered HOME") })
	if !handled {
		os.Exit(99)
	}
	os.Exit(code)
}
func TestExecutableProfileRecoveryOwnsTerminationSignals(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutableProfileRecoverySignalHelper$")
			command.Env = append(os.Environ(), "ACS_RECOVERY_SIGNAL_HELPER=1", "GORACE=atexit_sleep_ms=0")
			ready, err := command.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			command.Stdout = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(ready)
			if !scanner.Scan() || scanner.Text() != "recovery ready" {
				t.Fatal("recovery readiness absent", scanner.Text())
			}
			if err := command.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			err = command.Wait()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 130 {
				t.Fatalf("termination escaped signal-aware dispatch: %v %s", err, output.String())
			}
			var result struct {
				State      string                         `json:"state"`
				Diagnostic struct{ Code, Message string } `json:"diagnostic"`
			}
			if err := json.Unmarshal([]byte(output.String()), &result); err != nil || result.State != "not_committed" || result.Diagnostic.Code != "cancelled" || !strings.Contains(result.Diagnostic.Message, "inspection") {
				t.Fatalf("false cancellation outcome: %v %s", err, output.String())
			}
		})
	}
}
