package codexauthresource

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These exercise real files, locks and durable markers. Cleanup transitions are
// driven by the fixture, not by a Linux sandbox or a process-settlement proof.
func TestLinuxFileProviderStoreRefreshAndQuarantine(t *testing.T) {
	for _, outcome := range []string{"same identity", "changed identity", "cleanup pending", "uncertain commit"} {
		t.Run(outcome, func(t *testing.T) {
			_, _, original := fileProviderFixture(t)
			store, err := New(t.TempDir(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			provider := store.provider.(*fileCredentialProvider)
			if err := provider.Create(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			binding, metadata, err := store.AcquireStatus(context.Background(), "work")
			if err != nil || metadata != original.Metadata {
				t.Fatalf("acquire status: %v", err)
			}
			defer binding.Release()
			created := newProtectedTestSession(t)
			if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), testCleanupProofChallenge); err != nil {
				t.Fatal(err)
			}
			if err := binding.Project(created.HomeDirectory()); err != nil {
				t.Fatal(err)
			}
			projected := bytes.Replace(original.Auth, []byte("access-secret"), []byte("access-refreshed"), 1)
			wantRecord := credentialRecord{Metadata: original.Metadata, Auth: projected}
			wantDisposition, wantError := CommittedSameIdentityRefresh, error(nil)
			switch outcome {
			case "changed identity":
				projected = testChatGPTAuthJSON(t, "other-user", "workspace")
				wantRecord = original
				wantDisposition, wantError = DiscardedProjection, ErrProjectedAuthInvalid
			case "cleanup pending":
				wantRecord = original
				wantDisposition, wantError = QuarantinedUncertain, ErrBindingQuarantined
			case "uncertain commit":
				provider.syncDirectory = func(*privateDirectory) error { return unix.EIO }
				wantDisposition, wantError = QuarantinedUncertain, ErrBindingQuarantined
			}
			if err := os.WriteFile(filepath.Join(created.HomeDirectory(), ".codex", "auth.json"), projected, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := binding.MarkCleanupPending(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := binding.MarkRefreshAllowed(context.Background()); err != nil {
				t.Fatal(err)
			}
			if outcome != "cleanup pending" {
				if err := binding.MarkRecoverable(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			disposition, err := binding.FinalizeStatus(context.Background(), created.RootDirectory())
			if disposition != wantDisposition || !errors.Is(err, wantError) {
				t.Fatalf("refresh = (%s, %v)", disposition, err)
			}
			assertFileCredential(t, newPlatformProvider(), wantRecord)
			if err := binding.Release(); err != nil {
				t.Fatal(err)
			}
			// A successful write or released process lock cannot clear a durable
			// marker. This also covers rename-success/fsync-failure ambiguity.
			if err := store.Logout(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) {
				t.Fatalf("quarantined logout: %v", err)
			}
			if _, _, err := store.AcquireStatus(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) {
				t.Fatalf("quarantined status: %v", err)
			}
		})
	}
}

func TestLinuxFileProviderRecoveryRefresh(t *testing.T) {
	_, _, original := fileProviderFixture(t)
	locks, markers := t.TempDir(), t.TempDir()
	store, err := New(locks, markers)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.provider.Create(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	binding, _, err := store.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	created := newProtectedTestSession(t)
	for _, operation := range []func() error{
		func() error {
			return binding.PublishPrepared(context.Background(), created.RootDirectory(), testCleanupProofChallenge)
		},
		func() error { return binding.Project(created.HomeDirectory()) },
		func() error { return binding.MarkCleanupPending(context.Background()) },
		func() error { return binding.MarkRefreshAllowed(context.Background()) },
		func() error { return binding.MarkRecoverable(context.Background()) },
	} {
		if err := operation(); err != nil {
			t.Fatal(err)
		}
	}
	refreshed := bytes.Replace(original.Auth, []byte("access-secret"), []byte("recovered-access"), 1)
	if err := os.WriteFile(filepath.Join(created.HomeDirectory(), ".codex", "auth.json"), refreshed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(locks, markers)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := reopened.AcquireRecovery(context.Background(), "work")
	if err != nil || recovery == nil {
		t.Fatalf("reopen quarantine: %v", err)
	}
	defer recovery.Release()
	if disposition, err := recovery.FinalizeRecovery(context.Background(), created.RootDirectory()); err != nil || disposition != CommittedSameIdentityRefresh {
		t.Fatalf("recovery refresh = (%s, %v)", disposition, err)
	}
	assertFileCredential(t, newPlatformProvider(), credentialRecord{Metadata: original.Metadata, Auth: refreshed})
	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.DeleteMarkerAfterProjectionRemoval(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Release(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Logout(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxFileProviderCommitsLoginOnlyAfterSettlement(t *testing.T) {
	fileProviderFixture(t)
	store, err := New(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	root, auth := writeTestSessionAuth(t)
	if err := binding.PublishPrepared(context.Background(), root, testCleanupProofChallenge); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), root); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("login committed before settlement: %v", err)
	}
	if err := binding.MarkCleanupPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	metadata, err := binding.CommitLogin(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	assertFileCredential(t, newPlatformProvider(), credentialRecord{Metadata: metadata, Auth: auth})
}
