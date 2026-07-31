// backend/internal/capture/decode.go
package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeCapturedPacket converts a raw captured frame into a VIBES Packet.
// Returns nil for frames without an IPv4 layer (mirrors the live-capture path).
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
	srcPort, dstPort, protocol := extractPortsAndProtocol(packet)
	p := NewPacketWithPorts(ip.SrcIP.String(), ip.DstIP.String(), srcPort, dstPort, len(data), protocol)
	p.Source = source
	return p
}
