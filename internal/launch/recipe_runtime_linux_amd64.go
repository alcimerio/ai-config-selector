package launch

import (
	"debug/elf"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var errLinuxRecipe = errors.New("Linux experimental recipe rejected")

// Runtime discovery reads ELF metadata, never ldd or a target executable. The
// initial recipe deliberately excludes scripts, custom loaders/search paths,
// dlopen plugins and ambient loader configuration. Only exact files are bound.
type linuxRuntimeFile struct {
	path, destination string
	node              linuxFilesystemNode
}

func linuxRuntimeNode(file *os.File) (linuxFilesystemNode, error) {
	info, err := file.Stat()
	var x unix.Statx_t
	var fs unix.Statfs_t
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 ||
		unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &x) != nil ||
		x.Mask&unix.STATX_MNT_ID == 0 || unix.Fstatfs(int(file.Fd()), &fs) != nil {
		return linuxFilesystemNode{}, errLinuxRecipe
	}
	identity := identityFromFileInfo(info, info.Sys().(*syscall.Stat_t))
	if identity.links != 1 || !linuxDataFilesystem(fs.Type) {
		return linuxFilesystemNode{}, errLinuxRecipe
	}
	return linuxFilesystemNode{identity: identity, mountID: x.Mnt_id, filesystemType: fs.Type}, nil
}

func linuxOpenRuntime(path string) (*os.File, string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || !linuxCanonicalPlanPath(canonical) || linuxReservedHostTree(canonical) {
		return nil, "", errLinuxRecipe
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, canonical, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, "", errLinuxRecipe
	}
	return os.NewFile(uintptr(fd), "linux-runtime"), canonical, nil
}

func linuxELFDependencies(file *os.File) (string, []string, error) {
	f, err := elf.NewFile(file)
	if err != nil || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 ||
		(f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return "", nil, errLinuxRecipe
	}
	// debug/elf reads dynamic tags from section headers; the loader uses the
	// program header. Reject stripped or inconsistent metadata rather than
	// inspecting a different dependency table from the one that will execute.
	var dynamic *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			if dynamic != nil {
				return "", nil, errLinuxRecipe
			}
			dynamic = p
		}
	}
	section := f.SectionByType(elf.SHT_DYNAMIC)
	if (dynamic == nil) != (section == nil) || dynamic != nil &&
		(section.Offset != dynamic.Off || section.Addr != dynamic.Vaddr || section.Size != dynamic.Filesz || section.Entsize != 16 || section.Size%16 != 0) {
		return "", nil, errLinuxRecipe
	}
	if dynamic != nil {
		addresses, addressErr := f.DynValue(elf.DT_STRTAB)
		sizes, sizeErr := f.DynValue(elf.DT_STRSZ)
		if addressErr != nil || sizeErr != nil || len(addresses) != 1 || len(sizes) != 1 || int(section.Link) >= len(f.Sections) {
			return "", nil, errLinuxRecipe
		}
		stringsSection := f.Sections[section.Link]
		if stringsSection.Type != elf.SHT_STRTAB || stringsSection.Addr != addresses[0] || stringsSection.Size != sizes[0] {
			return "", nil, errLinuxRecipe
		}
		for _, table := range []*elf.Section{section, stringsSection} {
			mapped := false
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && table.Addr >= p.Vaddr && table.Size <= p.Filesz &&
					table.Addr-p.Vaddr <= p.Filesz-table.Size && p.Off <= table.Offset &&
					table.Offset-p.Off == table.Addr-p.Vaddr {
					mapped = true
				}
			}
			if !mapped {
				return "", nil, errLinuxRecipe
			}
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_AUDIT, elf.DT_DEPAUDIT, elf.DT_FILTER, elf.DT_AUXILIARY} {
		values, err := f.DynValue(tag)
		if err != nil || len(values) != 0 {
			return "", nil, errLinuxRecipe
		}
	}
	interpreter := ""
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if interpreter != "" || p.Filesz < 2 || p.Filesz > 4096 {
			return "", nil, errLinuxRecipe
		}
		data, err := io.ReadAll(io.LimitReader(p.Open(), 4097))
		if err != nil || len(data) != int(p.Filesz) || data[len(data)-1] != 0 || strings.ContainsRune(string(data[:len(data)-1]), 0) {
			return "", nil, errLinuxRecipe
		}
		interpreter = string(data[:len(data)-1])
		if interpreter != "/lib64/ld-linux-x86-64.so.2" && interpreter != "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" {
			return "", nil, errLinuxRecipe
		}
	}
	needed, err := f.ImportedLibraries()
	neededOffsets, offsetErr := f.DynValue(elf.DT_NEEDED)
	if err != nil || offsetErr != nil || len(needed) != len(neededOffsets) || len(needed) > 128 {
		return "", nil, errLinuxRecipe
	}
	for _, name := range needed {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00$") {
			return "", nil, errLinuxRecipe
		}
	}
	return interpreter, needed, nil
}

func linuxDiscoverRuntime(executable string, terminal bool) ([]linuxRuntimeFile, error) {
	queue := []string{executable}
	seen := map[string]bool{}
	var files []linuxRuntimeFile
	for len(queue) != 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] {
			continue
		}
		if len(seen) >= 128 {
			return nil, errLinuxRecipe
		}
		seen[path] = true
		file, canonical, err := linuxOpenRuntime(path)
		if err != nil {
			return nil, err
		}
		if path != executable && !withinOrEqual("/usr/lib", canonical) && !withinOrEqual("/lib", canonical) &&
			!withinOrEqual("/usr/lib64", canonical) && !withinOrEqual("/lib64", canonical) {
			_ = file.Close()
			return nil, errLinuxRecipe
		}
		node, nodeErr := linuxRuntimeNode(file)
		interpreter, needed, elfErr := linuxELFDependencies(file)
		_ = file.Close()
		if nodeErr != nil || elfErr != nil || path == executable && node.identity.mode.Perm()&0111 == 0 {
			return nil, errLinuxRecipe
		}
		files = append(files, linuxRuntimeFile{canonical, path, node})
		if interpreter != "" {
			queue = append(queue, interpreter)
		}
		for _, name := range needed {
			found := false
			for _, directory := range []string{"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"} {
				candidate := filepath.Join(directory, name)
				_, err := os.Lstat(candidate)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return nil, errLinuxRecipe
				}
				queue = append(queue, candidate)
				found = true
				break
			}
			if !found {
				return nil, errLinuxRecipe
			}
		}
	}
	if terminal {
		// A fixed TERM needs one database entry, never the whole terminfo tree.
		path := "/lib/terminfo/x/xterm"
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			path = "/usr/share/terminfo/x/xterm"
		}
		file, canonical, err := linuxOpenRuntime(path)
		if err != nil {
			return nil, err
		}
		node, err := linuxRuntimeNode(file)
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		files = append(files, linuxRuntimeFile{canonical, path, node})
	}
	return files, nil
}

// Aliases are exact read-only file mounts, not host symlinks or directory binds.
// This supplies the literal ELF interpreter/soname location on merged-/usr
// systems without exposing any extra files from /lib or /usr.
func linuxAddRuntimeAliases(plan *linuxFilesystemPlan, files []linuxRuntimeFile, denied []string) error {
	mounts := map[string]linuxMount{}
	for _, m := range plan.mounts[:len(plan.mounts)-1] {
		mounts[m.destination] = m
	}
	for _, f := range files {
		if f.path == f.destination {
			continue
		}
		if !linuxCanonicalPlanPath(f.destination) || linuxReservedHostTree(f.destination) {
			return errLinuxRecipe
		}
		for _, path := range denied {
			if pathsOverlap(path, f.destination) {
				return errLinuxRecipe
			}
		}
		for _, m := range mounts {
			if m.kind != linuxMountDirectory && pathsOverlap(m.destination, f.destination) {
				return errLinuxRecipe
			}
		}
		mounts[f.destination] = linuxMount{kind: linuxMountRuntimeAlias, source: f.path,
			destination: f.destination, identity: f.node.identity, mountID: f.node.mountID}
		plan.rules = append(plan.rules, linuxLandlockRule{f.destination, linuxReadFile})
		for p := filepath.Dir(f.destination); p != "/"; p = filepath.Dir(p) {
			if _, exists := mounts[p]; !exists {
				mounts[p] = linuxMount{kind: linuxMountDirectory, destination: p}
			}
		}
	}
	plan.mounts = nil
	for _, m := range mounts {
		plan.mounts = append(plan.mounts, m)
	}
	sort.Slice(plan.mounts, func(i, j int) bool { return plan.mounts[i].destination < plan.mounts[j].destination })
	plan.mounts = append(plan.mounts, linuxMount{kind: linuxMountSealRoot, destination: "/"})
	sort.Slice(plan.rules, func(i, j int) bool { return plan.rules[i].path < plan.rules[j].path })
	return nil
}
