package acceptance_test

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// These bytes were naturally persisted by locked Devin 3000.10.21 after its
// documented manual PKCE flow against a synthetic local backend. They were
// copied without rewriting from the recorded research case, not hand-authored.
//
//go:embed testdata/devin-synthetic-credentials.toml
var devinSyntheticCredentials []byte

const devinCredentialDigest = "2c8f2a5ad094b05d10c5bf22af343521bb10225c9a9883d818cc0fb6fe814558"

func devinCredentialEndpoint() (string, error) {
	h := sha256.Sum256(devinSyntheticCredentials)
	if len(devinSyntheticCredentials) != 175 || hex.EncodeToString(h[:]) != devinCredentialDigest {
		return "", errors.New("credential fixture provenance mismatch")
	}
	// The exact digest above fixes this syntax. This is not a general TOML parser.
	var endpoint string
	for _, line := range strings.Split(string(devinSyntheticCredentials), "\n") {
		if strings.HasPrefix(line, "api_server_url = ") {
			var err error
			endpoint, err = strconv.Unquote(strings.TrimPrefix(line, "api_server_url = "))
			if err != nil {
				return "", err
			}
		}
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("credential endpoint is not exact loopback origin")
	}
	return u.Host, nil
}

// home must be a newly created private temporary HOME owned by the harness.
// Create the exact destination exclusively; never replace existing credentials.
func copyDevinSyntheticCredentials(home string) (string, error) {
	endpoint, e := devinCredentialEndpoint()
	if e != nil {
		return "", e
	}
	dir := filepath.Join(home, ".local", "share", "devin")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	f, e := os.OpenFile(filepath.Join(dir, "credentials.toml"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	n, e := f.Write(devinSyntheticCredentials)
	if e == nil && n != len(devinSyntheticCredentials) {
		e = errors.New("short fixture copy")
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	return endpoint, e
}
