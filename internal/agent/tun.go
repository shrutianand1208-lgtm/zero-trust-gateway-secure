package agent

import (
	"fmt"
	"log"
)

// Tunnel is an abstraction over a virtual L3 interface (like a TUN device).
// Eventually, implementations will read/write raw IP packets.
// For now, LoggingTunnel just logs and does not manipulate real packets.
type Tunnel interface {
	Name() string
	Up() error
	Close() error
	SetAddress(ipCIDR string) error
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
}

// LoggingTunnel is a placeholder implementation used on macOS / dev.
// It only logs tunnel operations; it does not create real interfaces.
type LoggingTunnel struct {
	name string
}

func NewLoggingTunnel(name string) *LoggingTunnel {
	return &LoggingTunnel{name: name}
}

func (t *LoggingTunnel) Name() string {
	return t.name
}

func (t *LoggingTunnel) Up() error {
	log.Printf("[Tunnel] (logging) bringing up tunnel %s (no-op)", t.name)
	return nil
}

func (t *LoggingTunnel) Close() error {
	log.Printf("[Tunnel] (logging) closing tunnel %s (no-op)", t.name)
	return nil
}

func (t *LoggingTunnel) SetAddress(ipCIDR string) error {
	log.Printf("[Tunnel] (logging) would assign address %s to %s (no-op)", ipCIDR, t.name)
	return nil
}

func (t *LoggingTunnel) ReadPacket(buf []byte) (int, error) {
	log.Printf("[Tunnel] (logging) ReadPacket called on %s (no-op)", t.name)
	return 0, fmt.Errorf("ReadPacket not supported in logging tunnel")
}

func (t *LoggingTunnel) WritePacket(pkt []byte) error {
	log.Printf("[Tunnel] (logging) WritePacket called on %s (len=%d, no-op)", t.name, len(pkt))
	return nil
}
