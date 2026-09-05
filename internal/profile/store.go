package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

var ErrProfileExists = errors.New("Profile already exists")

type Store struct {
	profilesDir string
	codec       Codec
}

// Codec owns Profile envelope migration and category normalization.
type Codec interface {
	Normalize(Profile) (Profile, error)
	Decode([]byte) (Profile, error)
}

func NewStore(acsHome string, codec Codec) *Store {
	return &Store{profilesDir: filepath.Join(acsHome, "profiles"), codec: codec}
}

func (store *Store) Create(profile Profile) (string, error) {
	return store.CreateContext(context.Background(), profile)
}

// CreateContext encodes canonical Profile bytes above the revisioned repository.
// Cancellation before its commit decision leaves the named Profile unchanged;
// post-decision errors carry an explicit outcome and recovery requirement.
func (store *Store) CreateContext(ctx context.Context, profile Profile) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := ValidateName(profile.Name); err != nil {
		return "", err
	}
	normalized, err := store.codec.Normalize(profile)
	if err != nil {
		return "", err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(normalized); err != nil {
		return "", fmt.Errorf("encode Profile: %w", err)
	}
	repository := profilerepo.New(filepath.Dir(store.profilesDir))
	// An absent condition is name-bound and reusable; reading an occupied name
	// must not turn Create into replacement.
	expected, err := profilerepo.AbsentRevision(profile.Name)
	if err != nil {
		return "", err
	}
	outcome, err := repository.Apply(ctx, profilerepo.CreateRequest{Name: profile.Name, Expected: expected, Bytes: canonical.Bytes()})
	if err != nil {
		if errors.Is(err, profilerepo.ErrConflict) || errors.Is(err, os.ErrExist) {
			err = errors.Join(ErrProfileExists, err)
		}
		return "", &profilerepo.OutcomeError{Outcome: outcome, Err: err}
	}
	return store.profilePath(profile.Name), nil
}

func (store *Store) Load(name string) (Profile, error) {
	if err := ValidateName(name); err != nil {
		return Profile{}, err
	}
	contents, err := os.ReadFile(store.profilePath(name))
	if err != nil {
		return Profile{}, err
	}
	loaded, err := store.codec.Decode(contents)
	if err != nil {
		return Profile{}, fmt.Errorf("decode Profile %q: %w", name, err)
	}
	return loaded, nil
}

func (store *Store) profilePath(name string) string {
	return filepath.Join(store.profilesDir, name+".json")
}

// RecoverContext is an explicit mutation-owned entry point. Loads and ordinary
// inspection never call it. It uses the same stationary lock as CreateContext.
func (store *Store) RecoverContext(ctx context.Context) error {
	outcome, err := profilerepo.New(filepath.Dir(store.profilesDir)).Recover(ctx)
	if err != nil {
		return &profilerepo.OutcomeError{Outcome: outcome, Err: err}
	}
	return nil
}
