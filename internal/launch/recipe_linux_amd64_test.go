package launch

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestLinuxRecipeAdmissionIsClosed(t *testing.T) {
	_, err := linuxCompileRecipe(linuxRecipeAdmission{}, linuxShellRecipe, validatedProcessRequest{}, nil, false)
	assertLinuxUnsupported(t, err)
	_, err = linuxRunRecipe(context.Background(), linuxRecipeAdmission{}, linuxRecipe{}, nil, nil, nil, [3]*os.File{}, nil, nil)
	assertLinuxUnsupported(t, err)
	t.Setenv("ACS_LINUX_EXPERIMENTAL", "1")
	t.Setenv("ACS_LINUX_NATIVE_REQUIRED", "1")
	if len(nativeSandboxBackends()) != 0 {
		t.Fatal("environment registered a production backend")
	}
	assertLinuxUnsupported(t, NewProcessSandbox().Check(context.Background(), SandboxCheck{}))
}

func TestLinuxRecipePreparationFailureSettlesOrQuarantines(t *testing.T) {
	for _, failProof := range []bool{false, true} {
		c := linuxCleanupFixture(t)
		if failProof {
			if err := os.Mkdir(filepath.Join(c.lease.RootDir, sessionCleanupProofFile), 0700); err != nil {
				t.Fatal(err)
			}
		}
		result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{true}, linuxRecipe{session: c.lease.RootDir},
			nil, nil, nil, [3]*os.File{}, nil, c)
		if !errors.Is(err, errLinuxRecipe) || result.Exited || result.Settled == failProof {
			t.Fatalf("prepare failure: %+v %v", result, err)
		}
		if failProof {
			select {
			case <-c.CleanupUnproven():
			default:
				t.Fatal("failed proof was not quarantined")
			}
		} else {
			select {
			case <-c.CleanupDone():
			default:
				t.Fatal("no-child cleanup did not complete")
			}
		}
	}
}

func TestLinuxELFMetadataRejectsUnqualifiedFormats(t *testing.T) {
	for _, tc := range []struct {
		name        string
		machine     elf.Machine
		interpreter string
		dynamic     map[elf.DynTag]string
		valid       bool
	}{
		{name: "static", machine: elf.EM_X86_64, valid: true},
		{name: "glibc", machine: elf.EM_X86_64, interpreter: "/lib64/ld-linux-x86-64.so.2", valid: true},
		{name: "arm64", machine: elf.EM_AARCH64},
		{name: "custom-loader", machine: elf.EM_X86_64, interpreter: "/tmp/loader"},
		{name: "rpath", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_RPATH: "$ORIGIN"}},
		{name: "runpath", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_RUNPATH: "/tmp"}},
		{name: "audit", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_AUDIT: "evil.so"}},
		{name: "filter", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_FILTER: "evil.so"}},
		{name: "needed-path", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_NEEDED: "../evil.so"}},
		{name: "needed-soname", machine: elf.EM_X86_64, dynamic: map[elf.DynTag]string{elf.DT_NEEDED: "libc.so.6"}, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := linuxTestELF(t, tc.machine, tc.interpreter, tc.dynamic)
			_, _, err := linuxELFDependencies(file)
			if (err == nil) != tc.valid {
				t.Fatalf("ELF acceptance = %v, want %v", err, tc.valid)
			}
		})
	}
	file, err := os.CreateTemp(t.TempDir(), "script")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, _ = file.WriteString("#!/bin/bash\necho unsafe\n")
	if _, _, err := linuxELFDependencies(file); !errors.Is(err, errLinuxRecipe) {
		t.Fatal("script accepted as an ELF recipe")
	}
	metadata := linuxTestELF(t, elf.EM_X86_64, "", map[elf.DynTag]string{elf.DT_NEEDED: "libc.so.6"})
	if _, err := metadata.WriteAt([]byte{0, 0}, 56); err != nil {
		t.Fatal(err)
	} // e_phnum
	if _, _, err := linuxELFDependencies(metadata); err == nil {
		t.Fatal("dynamic tags without a loader program header accepted")
	}
}

// Minimal ELF files exercise metadata parsing without depending on installed
// targets, a compiler toolchain, or native confinement prerequisites.
func linuxTestELF(t *testing.T, machine elf.Machine, interpreter string, dynamic map[elf.DynTag]string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	writeAt := func(offset int64, value any) {
		if _, err := file.Seek(offset, 0); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(file, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64}
	copy(header.Ident[:], "\x7fELF\x02\x01\x01")
	var programs []elf.Prog64
	if interpreter != "" {
		data := []byte(interpreter + "\x00")
		programs = append(programs, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 192, Filesz: uint64(len(data))})
		writeAt(192, data)
	}
	if len(dynamic) != 0 {
		header.Shoff, header.Shnum = 512, 3
		stringsTable := []byte{0}
		var entries []elf.Dyn64
		for tag, value := range dynamic {
			entries = append(entries, elf.Dyn64{Tag: int64(tag), Val: uint64(len(stringsTable))})
			stringsTable = append(stringsTable, []byte(value+"\x00")...)
		}
		entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_STRTAB), Val: 384}, elf.Dyn64{Tag: int64(elf.DT_STRSZ), Val: uint64(len(stringsTable))}, elf.Dyn64{})
		programs = append(programs, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Off: 256, Vaddr: 256, Filesz: uint64(len(entries) * 16)},
			elf.Prog64{Type: uint32(elf.PT_LOAD), Filesz: 704})
		writeAt(256, entries)
		writeAt(384, stringsTable)
		writeAt(512, []elf.Section64{{}, {Type: uint32(elf.SHT_STRTAB), Off: 384, Addr: 384, Size: uint64(len(stringsTable))},
			{Type: uint32(elf.SHT_DYNAMIC), Off: 256, Addr: 256, Size: uint64(len(entries) * 16), Link: 1, Entsize: 16}})
	}
	if len(programs) != 0 {
		header.Phoff, header.Phnum = 64, uint16(len(programs))
		writeAt(64, programs)
	}
	writeAt(0, header)
	return file
}

func TestLinuxTerminalSetupFilterCannotWeakenTarget(t *testing.T) {
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for _, args := range [][6]uint64{
		{128, unix.TIOCSCTTY, 0}, {128, unix.TIOCSCTTY, 1}, {0, unix.TIOCSCTTY},
		{1<<32 | 128, unix.TIOCSCTTY}, {128, unix.TIOCSTI}, {128, unix.TIOCLINUX},
		{128, 1<<32 | unix.TIOCSTI}, {128, unix.TIOCVHANGUP},
	} {
		if got := linuxEvaluateFilter(t, unix.AUDIT_ARCH_X86_64, unix.SYS_IOCTL, args); got != deny {
			t.Fatal("target acquired terminal setup authority")
		}
		want := uint32(deny)
		if args == [6]uint64{128, unix.TIOCSCTTY, 0} {
			want = unix.SECCOMP_RET_ALLOW
		}
		if got := linuxEvaluateProgram(t, linuxSeccompFilterForSetup(true), unix.AUDIT_ARCH_X86_64, unix.SYS_IOCTL, args); got != want {
			t.Fatalf("setup filter args %v = %#x, want %#x", args, got, want)
		}
	}
}

func TestLinuxRecipeStdioModes(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "redirected")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if interactive, err := linuxRecipeStdioMode([3]*os.File{file, file, file}); err != nil || interactive {
		t.Fatal("redirected descriptors did not retain their mode")
	}
	master, slave, err := pty.Open()
	if err != nil {
		linuxNativeUnavailable(t, "private PTY allocation")
	}
	defer master.Close()
	defer slave.Close()
	if interactive, err := linuxRecipeStdioMode([3]*os.File{slave, slave, slave}); err != nil || !interactive {
		t.Fatal("interactive descriptors not detected")
	}
	if _, err := linuxRecipeStdioMode([3]*os.File{slave, file, file}); err == nil {
		t.Fatal("mixed terminal redirection accepted")
	}
	attrs, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linuxRecipeTerminal([3]*os.File{slave, file, file}, &linuxTerminalState{file: slave, attrs: *attrs}); err == nil {
		t.Fatal("redirected file used as an interactive terminal")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *after != *attrs {
		t.Fatal("rejected terminal mode changed attributes")
	}
}

func TestLinuxRecipeCompilesLiteralCommandAndReadonlyRuntime(t *testing.T) {
	linuxCleanupPrerequisites(t)
	f := linuxNewNativeFixture(t, false)
	request, tree := linuxRecipeFixtureRequest(t, f, true)
	request.arguments = []string{"a b", "$(touch never)", "; exit", "*.txt", "", "--"}
	want := append([]string{request.executable}, request.arguments...)
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxCommandRecipe, request, tree, false)
	if err != nil {
		t.Fatal(err)
	}
	request.arguments[0] = "changed"
	if !reflect.DeepEqual(recipe.wire.Argv, want) {
		t.Fatal("literal argv changed")
	}
	for _, m := range recipe.plan.mounts {
		if m.destination == request.workspace && m.kind != linuxMountReadOnly {
			t.Fatal("workspace is not read-only by default")
		}
		if m.destination == request.executable && m.kind != linuxMountReadOnly {
			t.Fatal("executable is writable")
		}
	}
	request.workspaceAccess = WorkspaceAccessReadWrite
	writable, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxCommandRecipe, request, tree, false)
	if err != nil {
		t.Fatal(err)
	}
	if planMount(t, writable.plan, request.workspace).kind != linuxMountReadWrite || planMount(t, writable.plan, request.executable).kind != linuxMountReadOnly {
		t.Fatal("explicit workspace write changed runtime authority")
	}
}

func TestLinuxShellRecipeUsesExactRuntimeFiles(t *testing.T) {
	linuxCleanupPrerequisites(t)
	f := linuxNewNativeFixture(t, false)
	request, tree := linuxRecipeFixtureRequest(t, f, true)
	request.executable, request.arguments = "", nil
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxShellRecipe, request, tree, true)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(recipe.wire.Executable) != "bash" || !reflect.DeepEqual(recipe.wire.Argv[1:], []string{"--noprofile", "--norc"}) {
		t.Fatal("wrong fixed shell")
	}
	for _, m := range recipe.plan.mounts {
		if strings.HasPrefix(m.destination, "/usr/") || strings.HasPrefix(m.destination, "/lib") {
			if m.kind != linuxMountDirectory && (m.kind != linuxMountReadOnly && m.kind != linuxMountRuntimeAlias || !m.identity.mode.IsRegular()) {
				t.Fatalf("broad or writable runtime mount: %+v", m)
			}
		}
	}
	request.arguments = []string{"-c", "arbitrary"}
	if _, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxShellRecipe, request, tree, false); err == nil {
		t.Fatal("caller changed fixed shell arguments")
	}
}

func TestLinuxRuntimeAliasesCannotMaskExistingAuthority(t *testing.T) {
	for _, access := range []PathAccess{PathAccessReadOnly, PathAccessReadWrite} {
		f := newLinuxPlanFixture()
		f.directory("/data/shared")
		f.grant("/data/shared", access)
		plan := f.compile(t)
		if err := linuxAddRuntimeAliases(&plan, []linuxRuntimeFile{{path: f.request.executable,
			destination: "/data/shared/injected", node: f.tree[f.request.executable]}}, nil); err == nil {
			t.Fatal("runtime alias overlaid existing Profile authority")
		}
	}
	f := newLinuxPlanFixture()
	plan := f.compile(t)
	if err := linuxAddRuntimeAliases(&plan, []linuxRuntimeFile{{path: f.request.executable,
		destination: "/lib64/loader", node: f.tree[f.request.executable]}}, nil); err != nil {
		t.Fatal(err)
	}
	if planMount(t, plan, "/lib64/loader").kind != linuxMountRuntimeAlias || planRights(plan, "/lib64/loader") != linuxReadFile {
		t.Fatal("runtime alias did not retain read-only file authority")
	}
	for _, denied := range []string{"/lib64", "/lib64/loader"} {
		plan := f.compile(t)
		if err := linuxAddRuntimeAliases(&plan, []linuxRuntimeFile{{path: f.request.executable,
			destination: "/lib64/loader", node: f.tree[f.request.executable]}}, []string{denied}); err == nil {
			t.Fatal("runtime alias resurrected an excluded/protected path")
		}
	}
}
