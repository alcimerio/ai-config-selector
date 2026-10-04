package codexcompat

import "testing"

func TestExactReviewedPolicy(t *testing.T) {
	for _, v := range []string{"0.149.1", "0.156.0", "0.149.0", "0.150.0", "0.160.0", "0.156.1", "0.156.0-beta", "", "0.999.0"} {
		want := v == "0.149.1" || v == "0.156.0"
		if AcceptsVersion(v) != want || AcceptsOutput("codex-cli "+v+"\n") != want {
			t.Fatalf("unexpected policy for %q", v)
		}
	}
	for _, output := range []string{"codex-cli 0.156.0 extra", "codex-cli 0.156.0\ncodex-cli 0.149.1", "0.156.0", "codex-cli  0.156.0"} {
		if AcceptsOutput(output) {
			t.Fatalf("accepted malformed output %q", output)
		}
	}
}
