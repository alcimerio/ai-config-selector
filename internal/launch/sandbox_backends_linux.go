package launch

// Linux remains unsupported until the complete sandbox described in
// docs/design/linux-support.md is qualified. Platform validation fails closed
// with a Linux-specific error; there is no backend or direct-exec fallback.
func nativeSandboxBackends() map[string]sandboxBackend { return nil }
