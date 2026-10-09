package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"golang.org/x/sys/unix"
)

var errInvalidProfileInput = errors.New("input must be one bounded regular file containing a supported version-3 Profile")

// readProfileDocument opens with O_NONBLOCK before inspecting the descriptor,
// so a FIFO or device cannot stall the command. Symlinks are deliberately
// followed; pathname replacement after open cannot redirect that read. The
// returned captured bytes, not the descriptor, begin the immutable candidate
// guarantee because concurrent in-place writes remain a filesystem possibility.
func readProfileDocument(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInvalidProfileInput
	}
	file := os.NewFile(uintptr(fd), "Profile input")
	if file == nil {
		unix.Close(fd)
		return nil, errInvalidProfileInput
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > profilerepo.MaxDocumentBytes {
		return nil, errInvalidProfileInput
	}
	contents, err := io.ReadAll(io.LimitReader(file, profilerepo.MaxDocumentBytes+1))
	if err != nil || len(contents) > profilerepo.MaxDocumentBytes || int64(len(contents)) != stat.Size {
		return nil, errInvalidProfileInput
	}
	return contents, nil
}

func (app App) createProfileFromDocument(ctx context.Context, source string, dryRun bool) int {
	if app.Categories == nil || app.Profiles == nil {
		return app.fail("declarative Profile creation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return app.fail("Profile creation was not started: %v", err)
	}
	reader := app.ReadProfileDocument
	if reader == nil {
		reader = readProfileDocument
	}
	contents, err := reader(source)
	if err != nil {
		return app.fail("read Profile document: %v", errInvalidProfileInput)
	}
	// Extract only the bounded identity needed to bind strict DecodeNamed. The
	// subsequent strict inspection rejects duplicates, extensions and mismatch.
	var envelope struct {
		Version int    `json:"version"`
		Name    string `json:"name"`
	}
	if json.Unmarshal(contents, &envelope) != nil || envelope.Version != profile.CurrentVersion || profile.ValidateName(envelope.Name) != nil {
		return app.fail("Profile document has unsupported or invalid structure")
	}
	candidate, err := app.Categories.DecodeNamed(envelope.Name, contents)
	if err != nil || candidate.Version != profile.CurrentVersion {
		return app.fail("Profile document has unsupported or invalid structure")
	}
	for _, overlay := range candidate.Overlays {
		if overlay.Support != "supported" {
			return app.fail("Profile document contains an unsupported target overlay")
		}
	}
	var canonical []byte
	candidate, canonical, err = profile.Canonicalize(app.Categories, candidate)
	if err != nil {
		return app.fail("canonicalize Profile document")
	}
	if dryRun {
		if _, err := app.Profiles.Load(candidate.Name); err == nil {
			return app.fail("destination Profile is occupied; nothing was changed")
		} else if !errors.Is(err, os.ErrNotExist) {
			return app.fail("destination is occupied or could not be safely proven absent; nothing was changed")
		}
		var preview bytes.Buffer
		fmt.Fprintf(&preview, "Dry run for Profile %q\n\nExact canonical version-3 Profile JSON (including final newline):\n", candidate.Name)
		preview.Write(canonical)
		fmt.Fprintln(&preview, "\nSelected Skill material, named authentication, target executables, native sandbox readiness, and runtime readiness was not checked.")
		fmt.Fprintln(&preview, "No Profile storage, lock, journal, Session, credential, input, or process was changed.")
		if written, err := app.Output.Write(preview.Bytes()); err != nil || written != preview.Len() {
			return app.fail("write Profile dry-run preview")
		}
		return 0
	}
	// CreateContext's single locked Apply first recovers any preceding operation
	// and then publishes this captured candidate. A separate recovery call would
	// create a race between recovery and the requested conditional creation.
	_, err = app.Profiles.CreateContext(ctx, candidate)
	return app.completeProfile("create Profile", savedProfile(err), fmt.Sprintf("Created Profile %q.\n", candidate.Name), creationCompletion)
}
