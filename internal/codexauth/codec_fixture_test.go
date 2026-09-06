package codexauth

import "github.com/alcimerio/ai-config-selector/internal/codexauthresource"

const maximumAuthJSONSize = codexauthresource.MaximumAuthJSONSize

func validateAuthJSON(name CredentialRef, contents []byte) (IdentityMetadata, error) {
	return codexauthresource.ValidateAuthJSON(name, contents)
}

func clearBytes(value []byte) {
	codexauthresource.ClearBytes(value)
}
