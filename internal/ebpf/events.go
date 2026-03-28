package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf/ringbuf"
)

// DenyEvent is the Go-side representation of struct deny_event from maps.h.
type DenyEvent struct {
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	HostnameHash uint64
	TimestampNs  uint64
	PolicyID     uint32
}

// EventHandler is called for each deny event read from the ringbuf.
type EventHandler func(DenyEvent)

// EventReader reads deny events from the BPF ringbuf map and dispatches
// them to the registered handler.
type EventReader struct {
	reader  *ringbuf.Reader
	handler EventHandler
	logger  *slog.Logger
}

// NewEventReader creates a new reader for the events ringbuf map.
func NewEventReader(loader *Loader, handler EventHandler, logger *slog.Logger) (*EventReader, error) {
	eventsMap := loader.EventsMap()
	if eventsMap == nil {
		return nil, fmt.Errorf("events map not available — BPF objects not loaded")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &EventReader{
		reader:  rd,
		handler: handler,
		logger:  logger,
	}, nil
}

// Run reads events in a loop until the context is cancelled.
func (er *EventReader) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		er.reader.Close()
	}()

	for {
		record, err := er.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				er.logger.Info("event reader closed")
				return
			}
			er.logger.Error("reading ringbuf event", "error", err)
			continue
		}

		evt, err := parseDenyEvent(record.RawSample)
		if err != nil {
			er.logger.Error("parsing deny event", "error", err)
			continue
		}

		er.handler(evt)
	}
}

func parseDenyEvent(data []byte) (DenyEvent, error) {
	// struct deny_event layout (packed):
	//   __be32 src_ip       (4)
	//   __be32 dst_ip       (4)
	//   __be16 src_port     (2)
	//   __be16 dst_port     (2)
	//   __u64  hostname_hash(8)  — offset 12, but padded to 16
	//   __u64  timestamp_ns (8)
	//   __u32  policy_id    (4)
	// Total with padding: 40 bytes
	const expectedSize = 40
	if len(data) < expectedSize {
		return DenyEvent{}, fmt.Errorf("event too short: %d < %d", len(data), expectedSize)
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, data[0:4])
	dstIP := make(net.IP, 4)
	copy(dstIP, data[4:8])

	return DenyEvent{
		SrcIP:        srcIP,
		DstIP:        dstIP,
		SrcPort:      binary.BigEndian.Uint16(data[8:10]),
		DstPort:      binary.BigEndian.Uint16(data[10:12]),
		HostnameHash: binary.LittleEndian.Uint64(data[16:24]),
		TimestampNs:  binary.LittleEndian.Uint64(data[24:32]),
		PolicyID:     binary.LittleEndian.Uint32(data[32:36]),
	}, nil
}
