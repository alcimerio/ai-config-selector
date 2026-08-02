package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrProfileExists = errors.New("Profile already exists")

type Store struct {
	profilesDir string
}

func NewStore(acsHome string) *Store {
	return &Store{profilesDir: filepath.Join(acsHome, "profiles")}
}

func (store *Store) Create(profile Profile) (string, error) {
	if err := ValidateName(profile.Name); err != nil {
		return "", err
	}
	normalized, err := normalizeCurrentProfile(profile)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(store.profilesDir, 0o700); err != nil {
		return "", fmt.Errorf("create Profile directory: %w", err)
	}
	if err := os.Chmod(store.profilesDir, 0o700); err != nil {
		return "", fmt.Errorf("secure Profile directory: %w", err)
	}

	temporary, err := os.CreateTemp(store.profilesDir, ".profile-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temporary Profile: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(normalized); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("encode Profile: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("secure Profile: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync Profile: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close Profile: %w", err)
	}

	path := store.profilePath(profile.Name)
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%w: %q", ErrProfileExists, profile.Name)
		}
		return "", fmt.Errorf("publish Profile: %w", err)
	}
	if directory, err := os.Open(store.profilesDir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return path, nil
}

func (store *Store) Load(name string) (Profile, error) {
	if err := ValidateName(name); err != nil {
		return Profile{}, err
	}
	contents, err := os.ReadFile(store.profilePath(name))
	if err != nil {
		return Profile{}, err
	}
	loaded, err := decodeProfile(contents)
	if err != nil {
		return Profile{}, fmt.Errorf("decode Profile %q: %w", name, err)
	}
	return loaded, nil
}

func decodeProfile(contents []byte) (Profile, error) {
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return Profile{}, err
	}
	switch envelope.Version {
	case 1:
		var legacy struct {
			Version         int             `json:"version"`
			Name            string          `json:"name"`
			Target          string          `json:"target"`
			SkillReferences json.RawMessage `json:"skillReferences"`
		}
		if err := json.Unmarshal(contents, &legacy); err != nil {
			return Profile{}, err
		}
		references, err := decodeSkillReferences(legacy.SkillReferences)
		if err != nil {
			return Profile{}, fmt.Errorf("decode version-1 skillReferences: %w", err)
		}
		return NewSkillsProfile(legacy.Name, legacy.Target, references), nil
	case CurrentVersion:
		var loaded Profile
		if err := json.Unmarshal(contents, &loaded); err != nil {
			return Profile{}, err
		}
		return normalizeCurrentProfile(loaded)
	default:
		return Profile{}, fmt.Errorf("unsupported schema version %d", envelope.Version)
	}
}

func (store *Store) profilePath(name string) string {
	return filepath.Join(store.profilesDir, name+".json")
}
