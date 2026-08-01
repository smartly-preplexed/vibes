// backend/internal/capture/pcap_record_reader.go
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket/layers"
)

var errPcapHeaderIncomplete = errors.New("pcap header incomplete")

const (
	pcapMagicLE      = 0xa1b2c3d4 // usec timestamps, written little-endian
	pcapMagicNanoLE  = 0xa1b23c4d // nsec timestamps
	pcapGlobalHeader = 24
	pcapRecordHeader = 16
	maxSanePacketLen = 256 * 1024 * 1024 // corrupt-length guard
)

// pcapRecordReader tails a classic-pcap file using stateless ReadAt calls at
// an explicit offset. A partial record (writer mid-append) leaves the offset
// untouched so the next poll retries — no EOF latching, no position corruption.
type pcapRecordReader struct {
	f         *os.File
	byteOrder binary.ByteOrder
	linkType  layers.LinkType
	offset    int64
}

func newPcapRecordReader(path string) (*pcapRecordReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, pcapGlobalHeader)
	n, err := f.ReadAt(hdr, 0)
	if n < pcapGlobalHeader {
		f.Close()
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, errPcapHeaderIncomplete
		}
		return nil, err
	}
	var order binary.ByteOrder
	magicLE := binary.LittleEndian.Uint32(hdr[0:4])
	magicBE := binary.BigEndian.Uint32(hdr[0:4])
	switch {
	case magicLE == pcapMagicLE || magicLE == pcapMagicNanoLE:
		order = binary.LittleEndian
	case magicBE == pcapMagicLE || magicBE == pcapMagicNanoLE:
		order = binary.BigEndian
	default:
		f.Close()
		return nil, fmt.Errorf("not a classic pcap file (magic %#x): %s", magicLE, path)
	}
	return &pcapRecordReader{
		f:         f,
		byteOrder: order,
		linkType:  layers.LinkType(order.Uint32(hdr[20:24])),
		offset:    pcapGlobalHeader,
	}, nil
}

func (r *pcapRecordReader) LinkType() layers.LinkType { return r.linkType }

// SeekToEnd positions the reader at the file's current end, so a subsequent
// Next() only returns records appended after this call — used for a
// cold-start tail so pre-existing ring contents are never replayed. This is
// safe even though records are variable-length: the file is only ever
// appended to (dumpcap writes whole records), so "current end of file" is
// always a record boundary, never mid-record.
func (r *pcapRecordReader) SeekToEnd() error {
	info, err := r.f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	// Raw file size is NOT reliably a record boundary: dumpcap, writing live at
	// high rate, can leave a partial record (or a partial 16-byte header) at the
	// frontier. Landing there mid-record makes the next read interpret payload
	// bytes as a record header → a garbage length → fatal "corrupt record".
	// Instead, walk complete records forward from the (header-aligned) current
	// offset to the last boundary at/before EOF. Only record headers are parsed,
	// in 1 MB buffered blocks, so this is fast even on a multi-GB file and it
	// delivers nothing (cold start still ignores pre-existing history).
	const blockSize = 1 << 20
	block := make([]byte, blockSize)
	for {
		if r.offset+pcapRecordHeader > size {
			return nil // no room for another header → frontier reached
		}
		toRead := size - r.offset
		if toRead > blockSize {
			toRead = blockSize
		}
		n, rerr := r.f.ReadAt(block[:toRead], r.offset)
		if n < pcapRecordHeader {
			if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
				return rerr
			}
			return nil
		}
		p := 0
		for p+pcapRecordHeader <= n {
			inclLen := int64(r.byteOrder.Uint32(block[p+8 : p+12]))
			if inclLen < 0 || inclLen > maxSanePacketLen {
				r.offset += int64(p)
				return nil // garbage length → partial/mid-write frontier
			}
			recEnd := int64(p) + pcapRecordHeader + inclLen
			if r.offset+recEnd > size {
				r.offset += int64(p)
				return nil // record not fully written yet → frontier
			}
			if recEnd > int64(n) {
				break // record spans past this block; refill from p
			}
			p = int(recEnd)
		}
		if p == 0 {
			// A single record larger than the block buffer (jumbo). Advance by it
			// directly; bounds already validated above for the header case.
			inclLen := int64(r.byteOrder.Uint32(block[8:12]))
			if inclLen < 0 || inclLen > maxSanePacketLen || r.offset+pcapRecordHeader+inclLen > size {
				return nil
			}
			r.offset += pcapRecordHeader + inclLen
			continue
		}
		r.offset += int64(p)
	}
}

// Next returns the next complete record's frame bytes. ok=false means no
// complete record is available yet (tail: retry later). err is fatal.
func (r *pcapRecordReader) Next() ([]byte, bool, error) {
	rec := make([]byte, pcapRecordHeader)
	if n, err := r.f.ReadAt(rec, r.offset); n < pcapRecordHeader {
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, false, nil
		}
		return nil, false, err
	}
	inclLen := int64(r.byteOrder.Uint32(rec[8:12]))
	if inclLen < 0 || inclLen > maxSanePacketLen {
		return nil, false, fmt.Errorf("corrupt pcap record length %d at offset %d", inclLen, r.offset)
	}
	data := make([]byte, inclLen)
	if n, err := r.f.ReadAt(data, r.offset+pcapRecordHeader); int64(n) < inclLen {
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, false, nil // partial record — retry next poll
		}
		return nil, false, err
	}
	r.offset += pcapRecordHeader + inclLen
	return data, true, nil
}

func (r *pcapRecordReader) Close() error { return r.f.Close() }
