package profilerepo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type identityCodec struct{}

func (identityCodec) Normalize(p profile.Profile) (profile.Profile, error) { return p, nil }
func (identityCodec) Decode(data []byte) (p profile.Profile, err error) {
	err = json.Unmarshal(data, &p)
	return
}

type unusedBuilder struct{ t *testing.T }

func (b unusedBuilder) BuildProfile(context.Context, string, category.Draft, builder.SaveFunc, io.Reader, io.Writer) (builder.Outcome, error) {
	b.t.Fatal("builder ran despite occupied name")
	return builder.Outcome{}, nil
}

func TestSameNameCreationRetryRecoversPublishedTransaction(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "recover", true: "blocked-recovery"}[blocked], func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestRepositoryProcessHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "ACS_REPOSITORY_HELPER=canonical-create", "ACS_REPOSITORY_ROOT="+root, "ACS_REPOSITORY_KILL=publish.link.after", "GORACE=atexit_sleep_ms=0")
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "reached kill point") {
				t.Fatalf("creation did not interrupt: %v %s", err, output)
			}
			directory := filepath.Join(root, "profiles")
			if blocked {
				if err := os.WriteFile(filepath.Join(directory, ".profile-transaction-future"), []byte("future metadata"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			app := cli.App{Profiles: profile.NewStore(root, identityCodec{}), Builder: unusedBuilder{t}, Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &stderr, Interactive: func(io.Reader, io.Writer) bool { return true }}
			code := app.Run(context.Background(), []string{"devin", "create-profile", "--name", "destination"})
			if code != 1 || stdout.Len() != 0 {
				t.Fatalf("unexpected retry outcome: %d %s", code, stdout.String())
			}
			if blocked {
				if !strings.Contains(stderr.String(), "recover Profile repository before creation") || strings.Contains(stderr.String(), "already exists") {
					t.Fatal("recovery failure hidden by duplicate precheck", stderr.String())
				}
			} else {
				if !strings.Contains(stderr.String(), "already exists") {
					t.Fatal("retry did not settle prior publication", stderr.String())
				}
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() != "destination.json" && entry.Name() != ".profile-transaction-lock" {
						t.Fatal("retry left evidence", entry.Name())
					}
				}
			}
			if _, err := app.Profiles.Load("destination"); err != nil {
				t.Fatal("retry damaged published Profile", err)
			}
		})
	}
}
