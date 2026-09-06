package executor

import "github.com/alcimerio/ai-config-selector/internal/codexauthresource"

const maximumAuthJSONSize = codexauthresource.MaximumAuthJSONSize
const recordVersion = codexauthresource.RecordVersion

func validateAuthJSON(name CredentialRef, contents []byte) (IdentityMetadata, error) {
	return codexauthresource.ValidateAuthJSON(name, contents)
}

func clearBytes(value []byte) {
	codexauthresource.ClearBytes(value)
}
