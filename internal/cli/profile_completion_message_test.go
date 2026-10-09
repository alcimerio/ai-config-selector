package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

func TestProfileCompletionErrorGuidanceByOutcome(t *testing.T) {
	injected := errors.New("injected")
	for _, test := range []struct {
		name     string
		outcome  profilerepo.Outcome
		format   profileCompletionFormat
		code     int
		contains []string
		absent   []string
	}{
		{name: "mutation committed reporting failed", outcome: profilerepo.Outcome{State: profilerepo.Committed}, format: mutationCompletion, code: 1, contains: []string{"delete Profile: Profile mutation committed; reporting failed"}, absent: []string{"acs profile recover"}},
		{name: "mutation committed cleanup failed", outcome: profilerepo.Outcome{State: profilerepo.Committed, RecoveryRequired: true}, format: mutationCompletion, code: 1, contains: []string{"delete Profile: Profile mutation committed; cleanup or reporting failed", "acs profile recover"}},
		{name: "mutation unknown", outcome: profilerepo.Outcome{State: profilerepo.Unknown}, format: mutationCompletion, code: 1, contains: []string{"delete Profile: Outcome unknown", "acs profile recover"}},
		{name: "mutation preceding recovery", outcome: profilerepo.Outcome{State: profilerepo.NotCommitted, RecoveryRequired: true}, format: mutationCompletion, code: 1, contains: []string{"delete Profile: Requested mutation not committed", "acs profile recover"}},
		{name: "creation unknown", outcome: profilerepo.Outcome{State: profilerepo.Unknown}, format: creationCompletion, code: 1, contains: []string{"Profile transaction outcome unknown", "acs profile recover"}},
		{name: "creation not committed", outcome: profilerepo.Outcome{State: profilerepo.NotCommitted}, format: creationCompletion, code: 1, contains: []string{"not committed; nothing was published"}, absent: []string{"acs profile recover"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := App{Output: &stdout, ErrorOutput: &stderr}
			code := app.profileCompletionError("delete Profile", &profilerepo.OutcomeError{Outcome: test.outcome, Err: injected}, test.format)
			got := stderr.String()
			if code != test.code || strings.Contains(got, "Profile Profile") {
				t.Fatalf("code=%d stderr=%q", code, got)
			}
			for _, want := range test.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("stderr %q does not contain %q", got, want)
				}
			}
			for _, unwanted := range test.absent {
				if strings.Contains(got, unwanted) {
					t.Fatalf("stderr %q unexpectedly contains %q", got, unwanted)
				}
			}
		})
	}
}

func TestProfileCompletionErrorCancellationIsNotAFailure(t *testing.T) {
	for _, format := range []profileCompletionFormat{creationCompletion, mutationCompletion, legacyCreationCompletion} {
		var stdout, stderr bytes.Buffer
		app := App{Output: &stdout, ErrorOutput: &stderr}
		if code := app.profileCompletionError("create Profile", context.Canceled, format); code != 130 || !strings.Contains(stdout.String(), "cancelled") {
			t.Fatalf("format=%d code=%d stdout=%q stderr=%q", format, code, stdout.String(), stderr.String())
		}
	}
}

func TestWriteCompleteReportsSilentShortWrite(t *testing.T) {
	writer := &mutationCompletionWriter{short: true}
	if err := writeComplete(writer, []byte("receipt")); err == nil || writer.calls != 1 {
		t.Fatalf("short write err=%v calls=%d", err, writer.calls)
	}
}
