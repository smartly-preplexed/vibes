// backend/internal/capture/decode_test.go
package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPFrame(t *testing.T, srcIP, dstIP string, srcPort, dstPort int) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("hi"))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeCapturedPacketTCP(t *testing.T) {
	frame := buildTCPFrame(t, "192.168.1.10", "10.0.0.5", 50123, 443)
	p := decodeCapturedPacket(frame, layers.LinkTypeEthernet, "dumpcap")
	if p == nil {
		t.Fatal("expected packet, got nil")
	}
	if p.Src != "192.168.1.10" || p.Dst != "10.0.0.5" {
		t.Fatalf("bad IPs: %s -> %s", p.Src, p.Dst)
	}
	if p.SrcPort != 50123 || p.DstPort != 443 {
		t.Fatalf("bad ports: %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.Protocol != ProtocolTCP {
		t.Fatalf("bad protocol: %s", p.Protocol)
	}
	if p.Source != "dumpcap" {
		t.Fatalf("bad source: %q", p.Source)
	}
	if p.Size != len(frame) {
		t.Fatalf("bad size: %d != %d", p.Size, len(frame))
	}
}

func TestDecodeCapturedPacketNonIPReturnsNil(t *testing.T) {
	if p := decodeCapturedPacket([]byte{0xde, 0xad, 0xbe, 0xef}, layers.LinkTypeEthernet, "dumpcap"); p != nil {
		t.Fatalf("expected nil for garbage frame, got %+v", p)
	}
}

// A Layer-2 frame (ARP here) must never become a node — no IPs to plot.
func TestDecodeCapturedPacketARPReturnsNil(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
		SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, SourceProtAddress: []byte{192, 168, 1, 2},
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{192, 168, 1, 1},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		t.Fatal(err)
	}
	if p := decodeCapturedPacket(buf.Bytes(), layers.LinkTypeEthernet, "dumpcap"); p != nil {
		t.Fatalf("expected nil for ARP (Layer-2) frame, got %+v", p)
	}
}

func TestValidIPv4(t *testing.T) {
	for _, s := range []string{"192.168.1.1", "10.0.0.5", "8.8.8.8", "0.0.0.0"} {
		if !validIPv4(s) {
			t.Errorf("expected %q valid", s)
		}
	}
	for _, s := range []string{"", "<nil>", "fe80::1", "not.an.ip.x", "256.1.1.1", "1.2.3"} {
		if validIPv4(s) {
			t.Errorf("expected %q invalid", s)
		}
	}
}
