//go:build !linux
// +build !linux

package agent

import "log"

type LinuxTun struct {
	name string
}

func NewLinuxTun(name string) (*LinuxTun, error) {
	log.Printf("[Tunnel][nonlinux] NewLinuxTun(%s) called on non-Linux; stub only", name)
	return &LinuxTun{name: name}, nil
}

func (t *LinuxTun) Name() string {
	return t.name
}

func (t *LinuxTun) Up() error {
	log.Printf("[Tunnel][nonlinux] Up() for %s (no-op)", t.name)
	return nil
}

func (t *LinuxTun) Close() error {
	log.Printf("[Tunnel][nonlinux] Close() for %s (no-op)", t.name)
	return nil
}

func (t *LinuxTun) SetAddress(ipCIDR string) error {
	log.Printf("[Tunnel][nonlinux] SetAddress(%s) for %s (no-op)", ipCIDR, t.name)
	return nil
}

// New in 6.2a
func (t *LinuxTun) ReadPacket(buf []byte) (int, error) {
	log.Printf("[Tunnel][nonlinux] ReadPacket on %s (no-op)", t.name)
	return 0, nil
}

func (t *LinuxTun) WritePacket(pkt []byte) error {
	log.Printf("[Tunnel][nonlinux] WritePacket on %s (len=%d, no-op)", t.name, len(pkt))
	return nil
}
