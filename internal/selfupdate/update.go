package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const repository = "alcimerio/ai-config-selector"
const guidance = "reinstall with the official release installer (README: Install a release)"
const maxArchive = 128 << 20

var ErrPublishedUncertain = errors.New("replacement published; durability or completion is uncertain")

type Config struct {
	// Set only by in-package tests and native fixture tests; production uses fixed URLs.
	Client                   *http.Client
	APIBase                  string
	Executable               string
	PlatformOS, PlatformArch string
}

type Result struct {
	Current, Target, Installation string
	Available, Changed, Downgrade bool
}

type release struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func ParseVersion(s string) ([3]uint64, error) {
	var v [3]uint64
	if !strings.HasPrefix(s, "v") {
		return v, errors.New("version must be vMAJOR.MINOR.PATCH")
	}
	parts := strings.Split(s[1:], ".")
	if len(parts) != 3 {
		return v, errors.New("version must be vMAJOR.MINOR.PATCH")
	}
	for i, p := range parts {
		if p == "" || len(p) > 1 && p[0] == '0' {
			return v, errors.New("version must be vMAJOR.MINOR.PATCH")
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return v, errors.New("version must be vMAJOR.MINOR.PATCH")
			}
		}
		n, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return v, errors.New("version component is too large")
		}
		v[i] = n
	}
	return v, nil
}
func Compare(a, b [3]uint64) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func Run(ctx context.Context, current, pin string, check bool, cfg Config) (Result, error) {
	out := Result{Current: current}
	if pin != "" {
		if _, e := ParseVersion(pin); e != nil {
			return out, e
		}
	}
	if cfg.PlatformOS == "" {
		cfg.PlatformOS = runtime.GOOS
	}
	if cfg.PlatformArch == "" {
		cfg.PlatformArch = runtime.GOARCH
	}
	if cfg.PlatformOS != "darwin" || cfg.PlatformArch != "arm64" {
		return out, errors.New("updates require macOS 26 on Apple Silicon")
	}
	base := cfg.APIBase
	if base == "" {
		base = "https://api.github.com/repos/" + repository + "/releases"
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second, CheckRedirect: safeRedirect}
	}
	endpoint := base + "/latest"
	if pin != "" {
		endpoint = base + "/tags/" + url.PathEscape(pin)
	}
	raw, e := get(ctx, client, endpoint, 1<<20)
	if e != nil {
		return out, fmt.Errorf("release metadata unavailable: %w", e)
	}
	var rel release
	if json.Unmarshal(raw, &rel) != nil {
		return out, errors.New("release metadata is malformed")
	}
	target, e := ParseVersion(rel.Tag)
	if e != nil || rel.Draft || rel.Prerelease || pin != "" && pin != rel.Tag {
		return out, errors.New("release is not a published stable numeric version")
	}
	out.Target = rel.Tag
	archiveName := "acs_" + strings.TrimPrefix(rel.Tag, "v") + "_darwin_arm64.tar.gz"
	assets := map[string]string{}
	for _, a := range rel.Assets {
		if a.Name == archiveName || a.Name == "SHA256SUMS" {
			if assets[a.Name] != "" {
				return out, errors.New("release contains duplicate required assets")
			}
			if cfg.APIBase == "" && a.URL != "https://github.com/"+repository+"/releases/download/"+rel.Tag+"/"+a.Name {
				return out, errors.New("release asset source is unexpected")
			}
			assets[a.Name] = a.URL
		}
	}
	if len(assets) != 2 {
		return out, errors.New("release is missing required assets")
	}
	for _, name := range []string{archiveName, "SHA256SUMS"} {
		u, e := url.Parse(assets[name])
		if e != nil || u.Scheme != "https" && cfg.APIBase == "" || u.User != nil || u.Fragment != "" {
			return out, errors.New("release asset URL is unsafe")
		}
	}
	cv, ce := ParseVersion(current)
	out.Available = ce == nil && Compare(cv, target) < 0
	out.Downgrade = ce == nil && Compare(cv, target) > 0
	if check {
		return out, nil
	}
	if ce != nil {
		return out, errors.New("development or unknown-version executable cannot self-update; " + guidance)
	}
	if pin == "" && Compare(cv, target) > 0 {
		return out, errors.New("installed version is newer than latest published release; use an explicit version to downgrade")
	}
	if pin == "" && Compare(cv, target) == 0 {
		return out, nil
	}
	exe := cfg.Executable
	if exe == "" {
		exe, e = os.Executable()
		if e != nil {
			return out, errors.New("cannot resolve running executable")
		}
	}
	install, e := preflight(exe, cfg.Executable == "")
	if e != nil {
		return out, e
	}
	out.Installation = install
	directory, e := pinDirectory(filepath.Dir(install))
	if e != nil {
		return out, e
	}
	defer directory.Close()
	original, originalHash, e := installedIdentity(directory, filepath.Base(install))
	if e != nil {
		return out, e
	}
	manifest, e := get(ctx, client, assets["SHA256SUMS"], 4096)
	if e != nil {
		return out, fmt.Errorf("checksum manifest unavailable: %w", e)
	}
	expected, e := checksum(manifest, archiveName)
	if e != nil {
		return out, e
	}
	archive, e := get(ctx, client, assets[archiveName], maxArchive)
	if e != nil {
		return out, fmt.Errorf("archive unavailable: %w", e)
	}
	sum := sha256.Sum256(archive)
	if sum != expected {
		return out, errors.New("archive checksum mismatch")
	}
	binary, e := extract(archive)
	if e != nil {
		return out, e
	}
	if e = verifyBinary(binary); e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if e = replace(ctx, install, binary, original, originalHash, directory); e != nil {
		if errors.Is(e, ErrPublishedUncertain) {
			out.Changed = true
		}
		return out, e
	}
	out.Changed = true
	return out, nil
}

func safeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || req.URL.Scheme != "https" {
		return errors.New("unsafe release redirect")
	}
	switch req.URL.Hostname() {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com":
		return nil
	}
	return errors.New("unsafe release redirect")
}
func get(ctx context.Context, c *http.Client, where string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", where, nil)
	if e != nil {
		return nil, errors.New("invalid release URL")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, e := c.Do(req)
	if e != nil {
		return nil, errors.New("network request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("release request failed")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, errors.New("release body could not be read")
	}
	if int64(len(b)) > limit {
		return nil, errors.New("release body exceeds size limit")
	}
	return b, nil
}
func checksum(raw []byte, name string) ([32]byte, error) {
	var out [32]byte
	seen := map[string]bool{}
	version := strings.TrimSuffix(strings.TrimPrefix(name, "acs_"), "_darwin_arm64.tar.gz")
	allowed := regexp.MustCompile(`^acs_` + regexp.QuoteMeta(version) + `_(darwin|linux)_(arm64|amd64)\.tar\.gz$`)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.ContainsRune(line, '\r') {
			return out, errors.New("checksum manifest is malformed")
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !allowed.MatchString(fields[1]) || seen[fields[1]] || len(seen) >= 4 {
			return out, errors.New("checksum manifest is malformed")
		}
		seen[fields[1]] = true
		b, e := hex.DecodeString(fields[0])
		if e != nil {
			return out, errors.New("checksum manifest is malformed")
		}
		if fields[1] == name {
			copy(out[:], b)
		}
	}
	if !seen[name] {
		return out, errors.New("selected archive checksum is missing")
	}
	return out, nil
}
func verifyBinary(binary []byte) error {
	m, e := macho.NewFile(bytes.NewReader(binary))
	if e != nil || m.Cpu != macho.CpuArm64 {
		return errors.New("archive executable is not Apple Silicon Mach-O")
	}
	defer m.Close()
	info, e := buildinfo.Read(bytes.NewReader(binary))
	if e != nil || info.Path != "github.com/alcimerio/ai-config-selector/cmd/acs" {
		return errors.New("archive executable has unexpected Go build identity")
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOOS" && setting.Value != "darwin" || setting.Key == "GOARCH" && setting.Value != "arm64" {
			return errors.New("archive executable targets an unexpected platform")
		}
	}
	return nil
}
func extract(raw []byte) ([]byte, error) {
	source := bytes.NewReader(raw)
	z, e := gzip.NewReader(source)
	if e != nil {
		return nil, errors.New("archive gzip is malformed")
	}
	defer z.Close()
	z.Multistream(false)
	bounded := &expandedReader{source: z, limit: 192 << 20}
	t := tar.NewReader(bounded)
	seen := map[string]bool{}
	var binary []byte
	total := int64(0)
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("archive tar is malformed")
		}
		if h.Name != "acs" && h.Name != "README.md" && h.Name != "LICENSE" || seen[h.Name] || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || h.Size < 0 || h.Size > 128<<20 {
			return nil, errors.New("archive contains unsafe entries")
		}
		seen[h.Name] = true
		total += h.Size
		if total > 192<<20 {
			return nil, errors.New("archive expands beyond limit")
		}
		b, e := io.ReadAll(io.LimitReader(t, h.Size+1))
		if e != nil || int64(len(b)) != h.Size {
			return nil, errors.New("archive entry is truncated")
		}
		if h.Name == "acs" {
			if h.Mode&0o111 == 0 {
				return nil, errors.New("archive executable is not executable")
			}
			binary = b
		}
	}
	if len(seen) != 3 || len(binary) == 0 {
		return nil, errors.New("archive entries are incomplete")
	}
	tail, e := io.ReadAll(io.LimitReader(bounded, 64<<10+1))
	if e != nil || len(tail) > 64<<10 {
		return nil, errors.New("archive gzip is truncated")
	}
	for _, b := range tail {
		if b != 0 {
			return nil, errors.New("archive has unexpected trailing content")
		}
	}
	if e = z.Close(); e != nil {
		return nil, errors.New("archive gzip is truncated")
	}
	if source.Len() != 0 {
		return nil, errors.New("archive contains another gzip member or trailing compressed data")
	}
	return binary, nil
}

type expandedReader struct {
	source      io.Reader
	read, limit int64
}

func (r *expandedReader) Read(p []byte) (int, error) {
	if r.read > r.limit {
		return 0, errors.New("archive expands beyond limit")
	}
	remaining := r.limit - r.read + 1
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, e := r.source.Read(p)
	r.read += int64(n)
	if r.read > r.limit {
		return 0, errors.New("archive expands beyond limit")
	}
	return n, e
}
func preflight(exe string, checkPATH bool) (string, error) {
	if !filepath.IsAbs(exe) || filepath.Base(exe) != "acs" {
		return "", errors.New("unsupported executable layout; " + guidance)
	}
	clean := filepath.Clean(exe)
	p := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(clean), "/"), "/") {
		if part == "" {
			continue
		}
		p = filepath.Join(p, part)
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("unsupported symlinked installation directory; " + guidance)
		}
	}
	st, e := os.Lstat(clean)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("unsupported executable layout; " + guidance)
	}
	uid := os.Getuid()
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || stat.Nlink != 1 {
		return "", errors.New("executable is not owned by current user; " + guidance)
	}
	dir, e := os.Stat(filepath.Dir(clean))
	if e != nil {
		return "", errors.New("cannot inspect installation directory")
	}
	ds, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || int(ds.Uid) != uid || dir.Mode().Perm()&0o200 == 0 {
		return "", errors.New("installation directory is not user-owned and writable; " + guidance)
	}
	if checkPATH {
		found, e := exec.LookPath("acs")
		if e != nil {
			return "", errors.New("acs is not on PATH; " + guidance)
		}
		fst, e := os.Stat(found)
		if e != nil || !os.SameFile(st, fst) {
			return "", errors.New("PATH selects a different acs executable; " + guidance)
		}
	}
	return clean, nil
}
func pinDirectory(path string) (*os.File, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("cannot pin installation directory")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, errors.New("installation directory contains an unsafe component")
		}
		fd = next
	}
	d := os.NewFile(uintptr(fd), "acs-installation-directory")
	pathInfo, e := os.Lstat(path)
	pinned, e2 := d.Stat()
	if e != nil || e2 != nil || !os.SameFile(pathInfo, pinned) {
		d.Close()
		return nil, errors.New("installation directory changed")
	}
	ps, ok := pinned.Sys().(*syscall.Stat_t)
	if !ok || int(ps.Uid) != os.Getuid() || pinned.Mode().Perm()&0200 == 0 {
		d.Close()
		return nil, errors.New("installation directory is not user-owned and writable")
	}
	return d, nil
}
func openNamed(d *os.File, name string) (*os.File, error) {
	fd, e := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), name), nil
}
func installedIdentity(d *os.File, name string) (os.FileInfo, [32]byte, error) {
	var zero [32]byte
	f, e := openNamed(d, name)
	if e != nil {
		return nil, zero, errors.New("installed executable changed")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, zero, errors.New("installed executable changed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Getuid() {
		return nil, zero, errors.New("installed executable ownership changed")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, maxArchive+1))
	if e != nil || n > maxArchive {
		return nil, zero, errors.New("installed executable cannot be read")
	}
	copy(zero[:], h.Sum(nil))
	return info, zero, nil
}
func sameNamedFile(d *os.File, name string, expected os.FileInfo) bool {
	f, e := openNamed(d, name)
	if e != nil {
		return false
	}
	defer f.Close()
	info, e := f.Stat()
	return e == nil && info.Mode().IsRegular() && os.SameFile(info, expected)
}
func replace(ctx context.Context, path string, binary []byte, original os.FileInfo, originalHash [32]byte, d *os.File) error {
	return replaceWithOps(ctx, path, binary, original, originalHash, d, unix.Renameat, func(f *os.File) error { return f.Sync() })
}
func replaceWithOps(ctx context.Context, path string, binary []byte, original os.FileInfo, originalHash [32]byte, d *os.File, rename func(int, string, int, string) error, syncDirectory func(*os.File) error) error {
	return replaceWithStageOps(ctx, path, binary, original, originalHash, d, rename, syncDirectory, func(f *os.File, b []byte) (int, error) { return f.Write(b) }, func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }, func(f *os.File) error { return f.Sync() })
}
func replaceWithStageOps(ctx context.Context, path string, binary []byte, original os.FileInfo, originalHash [32]byte, d *os.File, rename func(int, string, int, string) error, syncDirectory func(*os.File) error, writeStage func(*os.File, []byte) (int, error), chmodStage func(*os.File, os.FileMode) error, syncStage func(*os.File) error) error {
	lockFD, e := unix.Openat(int(d.Fd()), ".acs.update.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return errors.New("cannot lock installation directory")
	}
	lock := os.NewFile(uintptr(lockFD), "acs-update-lock")
	defer lock.Close()
	lockInfo, e := lock.Stat()
	if e != nil {
		return errors.New("installation lock is unsafe")
	}
	lockStat, lockOK := lockInfo.Sys().(*syscall.Stat_t)
	if !lockInfo.Mode().IsRegular() || !lockOK || lockStat.Nlink != 1 || int(lockStat.Uid) != os.Getuid() {
		return errors.New("installation lock is unsafe")
	}
	for {
		e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK {
			return errors.New("cannot lock installation directory")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	lockName, e := openNamed(d, ".acs.update.lock")
	if e != nil {
		return errors.New("installation lock changed")
	}
	lockNameInfo, e := lockName.Stat()
	lockName.Close()
	if e != nil || !os.SameFile(lockInfo, lockNameInfo) {
		return errors.New("installation lock changed")
	}
	before, beforeHash, e := installedIdentity(d, filepath.Base(path))
	if e != nil || !os.SameFile(original, before) || beforeHash != originalHash || before.Mode() != original.Mode() || before.Size() != original.Size() {
		return errors.New("installed executable changed before update")
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return errors.New("cannot name staged executable")
	}
	staged := ".acs.update." + hex.EncodeToString(random[:])
	fd, e := unix.Openat(int(d.Fd()), staged, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return errors.New("cannot stage replacement executable")
	}
	f := os.NewFile(uintptr(fd), staged)
	defer f.Close()
	stagedInfo, e := f.Stat()
	if e != nil {
		return errors.New("cannot inspect staged executable")
	}
	defer func() {
		if sameNamedFile(d, staged, stagedInfo) {
			_ = unix.Unlinkat(int(d.Fd()), staged, 0)
		}
	}()
	n, e := writeStage(f, binary)
	if e != nil || n != len(binary) {
		return errors.New("cannot write replacement executable")
	}
	if e = chmodStage(f, 0755); e != nil {
		return errors.New("cannot set replacement permissions")
	}
	if e = syncStage(f); e != nil {
		return errors.New("cannot sync replacement executable")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	dAgain, e := pinDirectory(filepath.Dir(path))
	if e != nil {
		return errors.New("installation directory changed before update")
	}
	dNow, e := dAgain.Stat()
	dAgain.Close()
	dOriginal, eOriginal := d.Stat()
	if e != nil || eOriginal != nil || !os.SameFile(dNow, dOriginal) {
		return errors.New("installation directory changed before update")
	}
	now, nowHash, e := installedIdentity(d, filepath.Base(path))
	if e != nil || !os.SameFile(original, now) || nowHash != originalHash || now.Mode() != original.Mode() || now.Size() != original.Size() {
		return errors.New("installed executable changed before update")
	}
	if !sameNamedFile(d, staged, stagedInfo) {
		return errors.New("staged executable changed before update")
	}
	stagedRead, e := openNamed(d, staged)
	if e != nil {
		return errors.New("staged executable changed before update")
	}
	stageNow, e := stagedRead.Stat()
	if e != nil {
		stagedRead.Close()
		return errors.New("staged executable changed before update")
	}
	stageStat, stageOK := stageNow.Sys().(*syscall.Stat_t)
	if !stageNow.Mode().IsRegular() || stageNow.Mode().Perm() != 0755 || !os.SameFile(stageNow, stagedInfo) || !stageOK || stageStat.Nlink != 1 || int(stageStat.Uid) != os.Getuid() {
		stagedRead.Close()
		return errors.New("staged executable permissions changed before update")
	}
	stagedHash := sha256.New()
	stagedN, e := io.Copy(stagedHash, io.LimitReader(stagedRead, int64(len(binary))+1))
	stagedRead.Close()
	wanted := sha256.Sum256(binary)
	if e != nil || stagedN != int64(len(binary)) || !bytes.Equal(stagedHash.Sum(nil), wanted[:]) {
		return errors.New("staged executable bytes changed before update")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = rename(int(d.Fd()), staged, int(d.Fd()), filepath.Base(path)); e != nil {
		return errors.New("cannot publish replacement executable")
	}
	if e = syncDirectory(d); e != nil {
		return fmt.Errorf("%w: directory sync failed; verify installed version", ErrPublishedUncertain)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: command was cancelled; verify installed version", ErrPublishedUncertain)
	}
	return nil
}
