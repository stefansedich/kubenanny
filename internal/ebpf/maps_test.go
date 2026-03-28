package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"
)

func TestIPToU32BE(t *testing.T) {
	tests := []struct {
		name    string
		ip      net.IP
		want    uint32
		wantErr bool
	}{
		{
			name: "standard IPv4",
			ip:   net.ParseIP("10.0.0.1"),
			want: binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}),
		},
		{
			name: "loopback",
			ip:   net.ParseIP("127.0.0.1"),
			want: binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}),
		},
		{
			name: "broadcast",
			ip:   net.ParseIP("255.255.255.255"),
			want: 0xFFFFFFFF,
		},
		{
			name: "all zeros",
			ip:   net.ParseIP("0.0.0.0"),
			want: 0x00000000,
		},
		{
			name: "IPv4-mapped IPv6",
			ip:   net.ParseIP("::ffff:192.168.1.1"),
			want: binary.NativeEndian.Uint32([]byte{192, 168, 1, 1}),
		},
		{
			name:    "pure IPv6 address",
			ip:      net.ParseIP("::1"),
			wantErr: true,
		},
		{
			name:    "nil IP",
			ip:      nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipToU32BE(tt.ip)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ipToU32BE(%v) = %#08x, want %#08x", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIPToU32BE_Roundtrip(t *testing.T) {
	// Verify that converting to uint32 and back preserves the IP.
	ips := []string{"10.0.0.1", "192.168.1.100", "172.16.0.254", "1.2.3.4"}
	for _, s := range ips {
		ip := net.ParseIP(s)
		u, err := ipToU32BE(ip)
		if err != nil {
			t.Fatalf("ipToU32BE(%s): %v", s, err)
		}
		var buf [4]byte
		binary.NativeEndian.PutUint32(buf[:], u)
		got := net.IP(buf[:]).String()
		if got != s {
			t.Errorf("roundtrip(%s) = %s", s, got)
		}
	}
}

func TestPolicyHostnameKey_Size(t *testing.T) {
	// policyHostnameKey must be exactly 16 bytes to match the C struct.
	if got := unsafe.Sizeof(policyHostnameKey{}); got != 16 {
		t.Errorf("sizeof(policyHostnameKey) = %d, want 16", got)
	}
}

func TestPodPolicyKey_Size(t *testing.T) {
	if got := unsafe.Sizeof(podPolicyKey{}); got != 4 {
		t.Errorf("sizeof(podPolicyKey) = %d, want 4", got)
	}
}

func TestPodPolicyVal_Size(t *testing.T) {
	if got := unsafe.Sizeof(podPolicyVal{}); got != 4 {
		t.Errorf("sizeof(podPolicyVal) = %d, want 4", got)
	}
}

func TestPolicyDefaultKey_Size(t *testing.T) {
	if got := unsafe.Sizeof(policyDefaultKey{}); got != 4 {
		t.Errorf("sizeof(policyDefaultKey) = %d, want 4", got)
	}
}
