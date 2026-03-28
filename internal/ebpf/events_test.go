package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseDenyEvent_Valid(t *testing.T) {
	// Build a 40-byte deny event matching the C struct layout.
	data := make([]byte, 40)

	// src_ip = 10.0.0.1 (network byte order)
	copy(data[0:4], net.ParseIP("10.0.0.1").To4())
	// dst_ip = 93.184.216.34
	copy(data[4:8], net.ParseIP("93.184.216.34").To4())
	// src_port = 54321 (big-endian)
	binary.BigEndian.PutUint16(data[8:10], 54321)
	// dst_port = 443 (big-endian)
	binary.BigEndian.PutUint16(data[10:12], 443)
	// padding bytes 12-15 are zero
	// hostname_hash at offset 16 (little-endian)
	binary.LittleEndian.PutUint64(data[16:24], 0xDEADBEEFCAFE)
	// timestamp_ns at offset 24 (little-endian)
	binary.LittleEndian.PutUint64(data[24:32], 1234567890)
	// policy_id at offset 32 (little-endian)
	binary.LittleEndian.PutUint32(data[32:36], 42)

	evt, err := parseDenyEvent(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !evt.SrcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("SrcIP = %v, want 10.0.0.1", evt.SrcIP)
	}
	if !evt.DstIP.Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("DstIP = %v, want 93.184.216.34", evt.DstIP)
	}
	if evt.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", evt.SrcPort)
	}
	if evt.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", evt.DstPort)
	}
	if evt.HostnameHash != 0xDEADBEEFCAFE {
		t.Errorf("HostnameHash = %#x, want 0xDEADBEEFCAFE", evt.HostnameHash)
	}
	if evt.TimestampNs != 1234567890 {
		t.Errorf("TimestampNs = %d, want 1234567890", evt.TimestampNs)
	}
	if evt.PolicyID != 42 {
		t.Errorf("PolicyID = %d, want 42", evt.PolicyID)
	}
}

func TestParseDenyEvent_TooShort(t *testing.T) {
	data := make([]byte, 10) // less than 40
	_, err := parseDenyEvent(data)
	if err == nil {
		t.Fatal("expected error for short data, got nil")
	}
}

func TestParseDenyEvent_ExactMinSize(t *testing.T) {
	data := make([]byte, 40)
	_, err := parseDenyEvent(data)
	if err != nil {
		t.Fatalf("40 bytes should parse without error, got: %v", err)
	}
}

func TestParseDenyEvent_ExtraBytes(t *testing.T) {
	// Larger buffer should still work (only first 40 bytes matter).
	data := make([]byte, 64)
	copy(data[0:4], net.ParseIP("192.168.1.1").To4())
	_, err := parseDenyEvent(data)
	if err != nil {
		t.Fatalf("extra bytes should not cause error, got: %v", err)
	}
}

func TestParseDenyEvent_ZeroBuf(t *testing.T) {
	data := make([]byte, 0)
	_, err := parseDenyEvent(data)
	if err == nil {
		t.Fatal("expected error for zero-length data, got nil")
	}
}

func TestParseDenyEvent_IPPreservation(t *testing.T) {
	// Verify source and destination IPs are independent copies.
	data := make([]byte, 40)
	copy(data[0:4], []byte{10, 0, 0, 1})
	copy(data[4:8], []byte{10, 0, 0, 2})

	evt, err := parseDenyEvent(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutating the parsed event's SrcIP should not affect DstIP.
	evt.SrcIP[0] = 99
	if evt.DstIP[0] == 99 {
		t.Fatal("SrcIP and DstIP share underlying memory")
	}
}

func TestParseDenyEvent_AllFields(t *testing.T) {
	// Test with specific non-zero values in all fields.
	data := make([]byte, 40)
	copy(data[0:4], []byte{172, 16, 0, 1})
	copy(data[4:8], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(data[8:10], 12345)
	binary.BigEndian.PutUint16(data[10:12], 80)
	binary.LittleEndian.PutUint64(data[16:24], 0xAAAABBBBCCCCDDDD)
	binary.LittleEndian.PutUint64(data[24:32], 9999999999)
	binary.LittleEndian.PutUint32(data[32:36], 100)

	evt, err := parseDenyEvent(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !evt.SrcIP.Equal(net.IPv4(172, 16, 0, 1)) {
		t.Errorf("SrcIP = %v, want 172.16.0.1", evt.SrcIP)
	}
	if !evt.DstIP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("DstIP = %v, want 8.8.8.8", evt.DstIP)
	}
	if evt.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", evt.SrcPort)
	}
	if evt.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", evt.DstPort)
	}
	if evt.HostnameHash != 0xAAAABBBBCCCCDDDD {
		t.Errorf("HostnameHash = %#x, want 0xAAAABBBBCCCCDDDD", evt.HostnameHash)
	}
	if evt.TimestampNs != 9999999999 {
		t.Errorf("TimestampNs = %d, want 9999999999", evt.TimestampNs)
	}
	if evt.PolicyID != 100 {
		t.Errorf("PolicyID = %d, want 100", evt.PolicyID)
	}
}
