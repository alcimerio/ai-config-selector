// Package diagnostics reports passive facts only. Its dependencies provide no
// process, provider, terminal, planner, Session or persistence operations.
package diagnostics

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type Check struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Code     string `json:"code"`
	NextStep string `json:"nextStep"`
}
type Result struct {
	FormatVersion int     `json:"formatVersion"`
	Operation     string  `json:"operation"`
	Target        string  `json:"target"`
	Checks        []Check `json:"checks"`
}

func result(operation, target string) Result {
	r := Result{FormatVersion: 1, Operation: operation, Target: target, Checks: []Check{}}
	for _, id := range []string{"profile.structure", "profile.sources", "host.platform", "backend.file", "executable.availability", "executable.version", "authentication", "runtime.enforcement"} {
		r.Checks = append(r.Checks, Check{id, "unchecked", "not_requested", "This fact was not requested by this command."})
	}
	r.set("executable.version", "unchecked", "not_probed", "Executable presence does not establish version compatibility; check the documented workflow requirements.")
	r.set("authentication", "unchecked", "not_queried", "No credential provider was queried; use the documented authentication workflow when needed.")
	r.set("runtime.enforcement", "unchecked", "not_probed", "Backend-file presence does not establish containment; normal launch performs required runtime verification.")
	return r
}
func (r *Result) set(id, status, code, next string) {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			r.Checks[i] = Check{id, status, code, next}
			return
		}
	}
}
func (r Result) ExitCode() int {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return 1
		}
	}
	return 0
}

// Doctor inspects only native platform metadata and trusted backend metadata;
// optional target lookup does not execute the file or query a version.
func Doctor(target string) Result {
	return doctor(target, inspectPlatform, backendAvailable, executableAvailable)
}
func doctor(target string, host func() (launch.Platform, error), backend func() bool, executable func(string) bool) Result {
	r := result("doctor", target)
	p, err := host()
	if err != nil {
		r.set("host.platform", "fail", "platform_unavailable", "Native host version could not be read; use a supported macOS 26 arm64 or Intel host.")
	} else if launch.ValidatePlatform(p) != nil {
		r.set("host.platform", "fail", "unsupported_platform", "Use supported macOS 26 on arm64 or Intel; Linux and other platforms are unsupported.")
	} else {
		r.set("host.platform", "pass", "supported_platform", "The host matches the supported platform policy.")
	}
	if err == nil && p.OS == "darwin" {
		if backend() {
			r.set("backend.file", "pass", "backend_available", "Trusted backend file is available; actual enforcement remains unchecked.")
		} else {
			r.set("backend.file", "fail", "backend_unavailable", "Restore the system-provided sandbox-exec file and its trusted ownership and permissions.")
		}
	} else {
		r.set("backend.file", "unchecked", "no_supported_backend", "Use a supported macOS host to inspect the native backend file.")
	}
	name := map[string]string{"devin": "devin", "sandbox": "/bin/zsh", "codex-auth": "codex"}[target]
	if name != "" {
		if executable(name) {
			r.set("executable.availability", "pass", "executable_available", "Workflow executable is available; version compatibility remains unchecked.")
		} else {
			r.set("executable.availability", "fail", "executable_unavailable", "Install the selected workflow executable with readable and executable permissions; PATH entries must be absolute for client lookup.")
		}
	}
	return r
}
func backendAvailable() bool {
	const path = "/usr/bin/sandbox-exec"
	return trustedBackendFile(path, os.Lstat, readableExecutable)
}

func trustedBackendFile(path string, lstat func(string) (os.FileInfo, error), accessible func(string) bool) bool {
	if path != "/usr/bin/sandbox-exec" {
		return false
	}
	info, err := lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && info.Mode().Perm()&0022 == 0 && rootOwned(info) && accessible(path)
}
func executableAvailable(name string) bool {
	paths := []string{name}
	if !filepath.IsAbs(name) {
		paths = nil
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if filepath.IsAbs(dir) {
				paths = append(paths, filepath.Join(dir, name))
			}
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && readableExecutable(path) {
			return true
		}
	}
	return false
}

func Validate(name string, home func() (string, error)) Result {
	r := result("profile.validate", "")
	inspected := profileinspect.Unavailable("show")
	directory := ""
	if profile.ValidateName(name) != nil {
		inspected = profileinspect.Store{}.Show(name)
	} else {
		var err error
		directory, err = home()
		if err != nil {
			inspected = profileinspect.Unavailable("show")
		} else {
			inspected = (profileinspect.Store{Home: directory}).Show(name)
		}
	}
	if inspected.ExitCode() != 0 {
		code := "storage_unavailable"
		if inspected.Diagnostic != nil {
			code = inspected.Diagnostic.Code
		} else if len(inspected.Entries) == 1 && inspected.Entries[0].Diagnostic != nil {
			code = inspected.Entries[0].Diagnostic.Code
		}
		r.set("profile.structure", "fail", code, "Use acs profile list and acs profile show NAME to inspect supported structure; restore or create a valid Profile.")
		r.set("profile.sources", "unchecked", "structure_required", "Correct the Profile structure before resolving selected Skill sources.")
		return r
	}
	r.set("profile.structure", "pass", "valid_structure", "Supported stored Profile structure; no migration or persistence write occurred.")
	references := []skills.SkillReference{}
	for _, category := range inspected.Entries[0].Categories {
		references = append(references, category.Selection...)
	}
	catalog, err := devin.DiscoverSelectedSkillCatalog(context.Background(), directory, references)
	if err != nil {
		r.set("profile.sources", "fail", "sources_unavailable", "Restore access to the selected global Skill sources and validate again.")
		return r
	}
	return resolveSources(r, references, catalog)
}
func resolveSources(r Result, references []skills.SkillReference, catalog []skills.SkillBundle) Result {
	if _, err := skills.ResolveReferences(references, catalog); err != nil {
		r.set("profile.sources", "fail", "selected_sources_unresolved", "Restore selected Skills as direct source entries with a regular SKILL.md, remove ambiguity, or create a new Profile selection.")
	} else {
		r.set("profile.sources", "pass", "selected_sources_resolved", "Selected references resolve under existing discovery rules; bundle contents and launch readiness were not validated.")
	}
	return r
}
