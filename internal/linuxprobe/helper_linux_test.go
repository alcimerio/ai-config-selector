package linuxprobe

import (
	"context"
	"reflect"
	"testing"
)

func TestProbeHelperNeverInheritsEnvironmentOrExecutesUserCommands(t *testing.T) {
	t.Setenv("SYNTHETIC_CREDENTIAL", "secret-value")
	t.Setenv("PATH", "/private/bin")
	cmd := helperCommand(context.Background(), "seccomp")
	if cmd.Path != "/proc/self/exe" || cmd.Dir != "/" || !reflect.DeepEqual(cmd.Args, []string{"/proc/self/exe", helperArgument, "seccomp"}) || !reflect.DeepEqual(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) || cmd.Stdin != nil {
		t.Fatal("probe helper acquired ambient authority")
	}
}

func TestProbeReceiptIsBounded(t *testing.T) {
	w := &receiptWriter{}
	if _, err := w.Write([]byte(helperReceipt)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("private helper output")); err == nil {
		t.Fatal("unbounded output accepted")
	}
}
