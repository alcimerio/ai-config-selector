package codexauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
)

const keychainService = "com.alcimerio.ai-config-selector.codex-auth"

var (
	errKeychainItemNotFound = errors.New("Keychain item not found")
	metadataValuePattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)
)

type keychainAttributes struct {
	Account string
	Comment string
}

type keychainClient interface {
	Add(service, account, comment string, secret []byte) error
	Update(service, account, comment string, secret []byte) error
	Attributes(service string, account *string) ([]keychainAttributes, error)
	Data(service, account string) ([]byte, error)
	Delete(service, account string) error
}

type unavailableKeychainClient struct{}

func (unavailableKeychainClient) Add(string, string, string, []byte) error {
	return ErrProviderUnavailable
}

func (unavailableKeychainClient) Update(string, string, string, []byte) error {
	return ErrProviderUnavailable
}

func (unavailableKeychainClient) Attributes(string, *string) ([]keychainAttributes, error) {
	return nil, ErrProviderUnavailable
}

func (unavailableKeychainClient) Data(string, string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}

func (unavailableKeychainClient) Delete(string, string) error {
	return ErrProviderUnavailable
}

type keychainProvider struct{ client keychainClient }

type metadataEnvelope struct {
	Version  int              `json:"version"`
	Identity IdentityMetadata `json:"identity"`
}

func newKeychainProvider() *keychainProvider {
	client, err := newNativeKeychainClient()
	if err != nil {
		client = unavailableKeychainClient{}
	}
	return &keychainProvider{client: client}
}

func (provider *keychainProvider) Metadata(
	ctx context.Context,
	name CredentialRef,
) (IdentityMetadata, bool, error) {
	if err := ctx.Err(); err != nil {
		return IdentityMetadata{}, false, err
	}
	account := string(name)
	attributes, err := provider.client.Attributes(keychainService, &account)
	if errors.Is(err, errKeychainItemNotFound) {
		return IdentityMetadata{}, false, nil
	}
	if err != nil || len(attributes) != 1 {
		return IdentityMetadata{}, false, ErrProviderUnavailable
	}
	metadata, err := decodeMetadata(attributes[0])
	if err != nil || metadata.Name != name {
		return IdentityMetadata{}, false, ErrProviderUnavailable
	}
	return metadata, true, nil
}

func (provider *keychainProvider) Create(ctx context.Context, record credentialRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMetadata(record.Metadata); err != nil {
		return ErrUnsupportedAuth
	}
	validated, err := validateAuthJSON(record.Metadata.Name, record.Auth)
	if err != nil || validated != record.Metadata {
		return ErrUnsupportedAuth
	}
	payload, err := encodeEnvelope(record.Auth)
	if err != nil {
		return ErrUnsupportedAuth
	}
	defer clearBytes(payload)
	comment, err := encodeMetadata(record.Metadata)
	if err != nil {
		return ErrUnsupportedAuth
	}
	if err := provider.client.Add(keychainService, string(record.Metadata.Name), comment, payload); err != nil {
		if errors.Is(err, ErrIdentityExists) {
			return ErrIdentityExists
		}
		return ErrProviderUnavailable
	}
	return nil
}

func (provider *keychainProvider) Replace(ctx context.Context, record credentialRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMetadata(record.Metadata); err != nil {
		return ErrUnsupportedAuth
	}
	validated, err := validateAuthJSON(record.Metadata.Name, record.Auth)
	if err != nil || validated != record.Metadata {
		return ErrUnsupportedAuth
	}
	payload, err := encodeEnvelope(record.Auth)
	if err != nil {
		return ErrUnsupportedAuth
	}
	defer clearBytes(payload)
	comment, err := encodeMetadata(record.Metadata)
	if err != nil {
		return ErrUnsupportedAuth
	}
	if err := provider.client.Update(keychainService, string(record.Metadata.Name), comment, payload); err != nil {
		return ErrProviderUnavailable
	}
	return nil
}

func (provider *keychainProvider) List(ctx context.Context) ([]IdentityMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attributes, err := provider.client.Attributes(keychainService, nil)
	if errors.Is(err, errKeychainItemNotFound) {
		return []IdentityMetadata{}, nil
	}
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	identities := make([]IdentityMetadata, 0, len(attributes))
	seen := make(map[CredentialRef]struct{}, len(attributes))
	for _, item := range attributes {
		metadata, err := decodeMetadata(item)
		if err != nil {
			return nil, ErrProviderUnavailable
		}
		if _, exists := seen[metadata.Name]; exists {
			return nil, ErrProviderUnavailable
		}
		seen[metadata.Name] = struct{}{}
		identities = append(identities, metadata)
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left].Name < identities[right].Name })
	return identities, nil
}

func (provider *keychainProvider) Load(
	ctx context.Context,
	name CredentialRef,
) (credentialRecord, bool, error) {
	metadata, exists, err := provider.Metadata(ctx, name)
	if err != nil || !exists {
		return credentialRecord{}, exists, err
	}
	payload, err := provider.client.Data(keychainService, string(name))
	if errors.Is(err, errKeychainItemNotFound) {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	if err != nil {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	defer clearBytes(payload)
	auth, err := decodeEnvelope(payload)
	if err != nil {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	validated, err := validateAuthJSON(name, auth)
	if err != nil || validated != metadata {
		clearBytes(auth)
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	return credentialRecord{Metadata: metadata, Auth: auth}, true, nil
}

func (provider *keychainProvider) Delete(ctx context.Context, name CredentialRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := provider.client.Delete(keychainService, string(name))
	if errors.Is(err, errKeychainItemNotFound) {
		return nil
	}
	if err != nil {
		return ErrProviderUnavailable
	}
	return nil
}

func encodeMetadata(metadata IdentityMetadata) (string, error) {
	payload, err := json.Marshal(metadataEnvelope{Version: recordVersion, Identity: metadata})
	return string(payload), err
}

func decodeMetadata(attributes keychainAttributes) (IdentityMetadata, error) {
	if err := rejectDuplicateJSONKeys([]byte(attributes.Comment)); err != nil {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	decoder := json.NewDecoder(bytes.NewBufferString(attributes.Comment))
	decoder.DisallowUnknownFields()
	var envelope metadataEnvelope
	if err := decoder.Decode(&envelope); err != nil || envelope.Version != recordVersion {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	var additional any
	if err := decoder.Decode(&additional); !errors.Is(err, io.EOF) || string(envelope.Identity.Name) != attributes.Account {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	if err := validateMetadata(envelope.Identity); err != nil {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	return envelope.Identity, nil
}

func validateMetadata(metadata IdentityMetadata) error {
	if _, err := ParseCredentialRef(string(metadata.Name)); err != nil {
		return err
	}
	if metadata.Method != LoginMethodChatGPT {
		return ErrUnsupportedAuth
	}
	if metadata.Workspace != "" && !metadataValuePattern.MatchString(metadata.Workspace) {
		return ErrUnsupportedAuth
	}
	const prefix = "sha256:"
	if len(metadata.Fingerprint) != len(prefix)+sha256HexLength || metadata.Fingerprint[:len(prefix)] != prefix {
		return ErrUnsupportedAuth
	}
	if decoded, err := hex.DecodeString(metadata.Fingerprint[len(prefix):]); err != nil || len(decoded) != sha256HexLength/2 {
		return ErrUnsupportedAuth
	}
	return nil
}

const sha256HexLength = 64
