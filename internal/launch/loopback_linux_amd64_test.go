package launch

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLinuxLoopbackNotificationABI(t *testing.T) {
	if unsafe.Sizeof(linuxSeccompNotif{}) != 80 || unsafe.Sizeof(linuxSeccompResp{}) != 24 || unsafe.Sizeof(linuxSeccompAddFD{}) != 24 || unsafe.Sizeof(linuxSeccompData{}) != 64 {
		t.Fatalf("notif=%d resp=%d addfd=%d data=%d", unsafe.Sizeof(linuxSeccompNotif{}), unsafe.Sizeof(linuxSeccompResp{}), unsafe.Sizeof(linuxSeccompAddFD{}), unsafe.Sizeof(linuxSeccompData{}))
	}
	if err := linuxLoopbackNotifSizes(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxLoopbackPolicyMatchesCopiedAddress(t *testing.T) {
	resolvers := linuxParseResolvers("# comment\nnameserver 10.0.0.2\nnameserver 127.0.0.53\nnameserver not-an-ip\n")
	if len(resolvers) != 2 {
		t.Fatalf("resolvers=%v", resolvers)
	}
	allow := linuxLoopbackPolicy{Ports: []int{8080, 1455}}
	deny := linuxLoopbackPolicy{}
	cases := []struct {
		addr []byte
		pol  linuxLoopbackPolicy
		ok   bool
	}{
		{v4(127, 0, 0, 1, 9), deny, false},
		{v4(127, 0, 0, 2, 9), deny, false},
		{v4(8, 8, 8, 8, 9), deny, true},
		{v4(8, 8, 8, 8, 8080), deny, true},
		{v4(127, 0, 0, 1, 8080), allow, true},
		{v4(127, 255, 255, 255, 1455), allow, true},
		{v4(127, 0, 0, 1, 9), allow, false},
		{v4(10, 0, 0, 2, 53), deny, true},
		{v4(127, 0, 0, 53, 53), deny, true},
		{v4(127, 0, 0, 1, 53), deny, false},
		{v6(netip.MustParseAddr("::1"), 9), deny, false},
		{v6(netip.MustParseAddr("::1"), 8080), allow, true},
		{v6(netip.MustParseAddr("::ffff:127.0.0.1"), 9), deny, false},
		{v6(netip.MustParseAddr("::ffff:127.0.0.2"), 8080), allow, true},
		{v6(netip.MustParseAddr("2001:db8::1"), 9), deny, true},
		{[]byte{unix.AF_UNIX, 0, 'x'}, deny, true},
		{[]byte{0}, deny, false},
		{nil, deny, true},
	}
	for _, tc := range cases {
		if got := linuxLoopbackPermitted(tc.pol, tc.addr, resolvers); got != tc.ok {
			t.Errorf("addr %x allow=%v got %v", tc.addr, tc.ok, got)
		}
	}
}

func v4(a, b, c, d byte, port int) []byte {
	raw := make([]byte, 16)
	raw[0] = unix.AF_INET
	raw[2] = byte(port >> 8)
	raw[3] = byte(port)
	raw[4], raw[5], raw[6], raw[7] = a, b, c, d
	return raw
}

func v6(ip netip.Addr, port int) []byte {
	raw := make([]byte, 28)
	raw[0] = unix.AF_INET6
	raw[2] = byte(port >> 8)
	raw[3] = byte(port)
	addr := ip.As16()
	copy(raw[8:24], addr[:])
	return raw
}
