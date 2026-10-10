package launch

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
)

func TestLinuxDevinAdmissionAndArguments(t *testing.T) {
	_, err := linuxCompileRecipe(linuxRecipeAdmission{}, linuxDevinRecipe, validatedProcessRequest{}, nil, false)
	assertLinuxUnsupported(t, err)
	for _, arguments := range [][]string{{"--version"}, {"auth", "status"}, {"skills", "list", "--json"}, {"mcp", "list"}} {
		if !linuxDevinArguments(arguments) {
			t.Fatalf("reviewed preflight rejected: %v", arguments)
		}
	}
	for _, arguments := range [][]string{nil, {"auth", "login"}, {"--version", "--config", "/tmp/config"}, {"skills", "list"}, {"mcp", "add"}, {"--respect-workspace-trust", "false"}} {
		if linuxDevinArguments(arguments) {
			t.Fatalf("unreviewed invocation accepted: %v", arguments)
		}
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("ACS_LINUX_EXPERIMENTAL", "1")
	_, err = linuxCompileRecipe(linuxRecipeAdmission{true}, linuxDevinRecipe,
		validatedProcessRequest{executable: "devin", arguments: []string{"--version"}}, nil, false)
	if err == nil {
		t.Fatal("Devin qualification searched PATH")
	}
	assertLinuxUnsupported(t, NewProcessSandbox().Check(context.Background(), SandboxCheck{Executable: "devin"}))
}

func TestLinuxDevinVerifiesStaticELFAndDigest(t *testing.T) {
	for _, tc := range []struct {
		name, interpreter string
		machine           elf.Machine
		dynamic           map[elf.DynTag]string
		valid             bool
	}{
		{name: "static", machine: elf.EM_X86_64, valid: true},
		{name: "arm64-deferred", machine: elf.EM_AARCH64},
		{name: "dynamic-loader", machine: elf.EM_X86_64, interpreter: "/lib64/ld-linux-x86-64.so.2"},
		{name: "extra-library", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_NEEDED: "libc.so.6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := linuxTestELF(t, tc.machine, tc.interpreter, tc.dynamic)
			info, _ := file.Stat()
			hash := sha256.New()
			if _, err := io.Copy(hash, io.NewSectionReader(file, 0, info.Size())); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", hash.Sum(nil))
			if err := linuxVerifyDevinELF(file, info.Size(), digest); (err == nil) != tc.valid {
				t.Fatalf("static target qualification = %v, want accepted=%v", err, tc.valid)
			}
			for _, mismatch := range []struct {
				size   int64
				digest string
			}{{info.Size() + 1, digest}, {info.Size(), devinruntime.LinuxAMD64BinarySHA256}} {
				if linuxVerifyDevinELF(file, mismatch.size, mismatch.digest) == nil {
					t.Fatal("size/digest mismatch accepted")
				}
			}
		})
	}
}

func TestLinuxDevinRuntimeRejectsUnpinnedAndUnsafeFiles(t *testing.T) {
	file := linuxTestELF(t, elf.EM_X86_64, "", nil)
	if err := file.Chmod(0500); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file.Name(), filepath.Dir(file.Name()), "/missing/devin"} {
		if _, err := linuxDevinRuntime(path); err == nil {
			t.Fatal("unlocked target accepted")
		}
	}
	// The larger reviewed target must not raise the generic runtime limit.
	large, err := os.CreateTemp(t.TempDir(), "large")
	if err != nil {
		t.Fatal(err)
	}
	defer large.Close()
	if err := large.Truncate(devinruntime.LinuxAMD64BinarySize); err != nil {
		t.Fatal(err)
	}
	if _, err := linuxRuntimeNode(large); err == nil {
		t.Fatal("generic runtime accepted an oversized file")
	}
}

func TestLinuxDevinTransportUsesPrivateXDGDirectories(t *testing.T) {
	w := linuxTestWire()
	lease := linuxTestLease(t, nil)
	transport, err := linuxWriteTransport(w, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	_, env, err := linuxReadTransport(transport)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range env {
		if len(entry) >= 4 && entry[:4] == "XDG_" {
			got = append(got, entry)
		}
	}
	want := []string{"XDG_CONFIG_HOME=" + w.Home + "/.config", "XDG_DATA_HOME=" + w.Home + "/.local/share",
		"XDG_CACHE_HOME=" + w.Home + "/.cache", "XDG_STATE_HOME=" + w.Home + "/.local/state"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("XDG transport = %v", got)
	}
}
