// backend/internal/capture/decode.go
package capture

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// validIPv4 reports whether s is a real, dotted-quad IPv4 address. This is the
// single gate that keeps Layer-2 / non-IP / malformed frames out of the graph:
// a truncated or mis-parsed IPv4 header yields a nil SrcIP whose String() is
// "<nil>", and IPv6 / ARP / STP frames yield empty or non-dotted strings — all
// of which would otherwise render as blank, IP-less nodes.
func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// decodeCapturedPacket converts a raw captured frame into a VIBES Packet.
// Returns nil for anything without a valid IPv4 src AND dst (drops all Layer-2,
// non-IPv4, and malformed frames — no blank nodes).
func decodeCapturedPacket(data []byte, linkType layers.LinkType, source string) *Packet {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil
	}
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	if !validIPv4(srcIP) || !validIPv4(dstIP) {
		return nil
	}
	srcPort, dstPort, protocol := extractPortsAndProtocol(packet)
	p := NewPacketWithPorts(srcIP, dstIP, srcPort, dstPort, len(data), protocol)
	p.Source = source
	return p
}
