//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// Constants for TUN device configuration.
const (
	ifnamsiz   = 16
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
	cTUNSETIFF = 0x400454ca
)

// ifreq mirrors the C struct ifreq for TUNSETIFF ioctl.
type ifreq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte // padding to make the struct 40 bytes
}

// LinuxTun is a Linux TUN interface implementation backed by /dev/net/tun.
type LinuxTun struct {
	name string
	file *os.File // handle to /dev/net/tun
}

// NewLinuxTun creates a new LinuxTun with the given interface name.
// The actual device is created and configured in Up().
func NewLinuxTun(name string) (*LinuxTun, error) {
	log.Printf("[Tunnel][linux] NewLinuxTun(%s)", name)
	return &LinuxTun{name: name}, nil
}

func (t *LinuxTun) Name() string {
	return t.name
}

// Up creates the TUN device via /dev/net/tun (ioctl TUNSETIFF) and brings it up.
func (t *LinuxTun) Up() error {
	if t.file != nil {
		// Already opened and configured.
		log.Printf("[Tunnel][linux] TUN %s already up", t.name)
		return nil
	}

	log.Printf("[Tunnel][linux] Opening /dev/net/tun for %s", t.name)

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreq
	// Copy interface name into req.Name (null-terminated C string).
	if len(t.name) >= ifnamsiz {
		return fmt.Errorf("tunnel name %q too long (max %d)", t.name, ifnamsiz-1)
	}
	copy(req.Name[:], t.name)
	req.Flags = cIFF_TUN | cIFF_NO_PI

	// Issue ioctl(TUNSETIFF) to create/attach TUN interface.
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(cTUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = f.Close()
		return fmt.Errorf("ioctl TUNSETIFF for %s failed: %v", t.name, errno)
	}

	log.Printf("[Tunnel][linux] TUNSETIFF succeeded for %s", t.name)
	t.file = f

	// Bring interface up: ip link set <name> up
	upCmd := exec.Command("ip", "link", "set", t.name, "up")
	out, err := upCmd.CombinedOutput()
	if err != nil {
		log.Printf("[Tunnel][linux] ERROR bringing up TUN %s: %v, output=%s",
			t.name, err, string(out))
		return err
	}

	log.Printf("[Tunnel][linux] TUN %s created and brought up", t.name)
	return nil
}

// SetAddress assigns an IP/32 to the TUN device, e.g. 100.64.0.10/32.
func (t *LinuxTun) SetAddress(ipCIDR string) error {
	log.Printf("[Tunnel][linux] Assigning address %s to %s", ipCIDR, t.name)

	cmd := exec.Command("ip", "addr", "add", ipCIDR, "dev", t.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		// Ignore benign errors when the address already exists.
		if !strings.Contains(outStr, "File exists") &&
			!strings.Contains(outStr, "RTNETLINK answers: File exists") &&
			!strings.Contains(outStr, "Address already assigned") {
			log.Printf("[Tunnel][linux] ERROR assigning %s to %s: %v, output=%s",
				ipCIDR, t.name, err, outStr)
			return err
		}
		log.Printf("[Tunnel][linux] Address %s already present on %s, continuing", ipCIDR, t.name)
	}

	log.Printf("[Tunnel][linux] Assigned %s to %s", ipCIDR, t.name)
	return nil
}

// ReadPacket reads a single packet from the TUN interface into buf and returns
// the number of bytes read.
func (t *LinuxTun) ReadPacket(buf []byte) (int, error) {
	if t.file == nil {
		return 0, fmt.Errorf("ReadPacket called but TUN file is nil for %s", t.name)
	}

	n, err := syscall.Read(int(t.file.Fd()), buf)
	if err != nil {
		return n, fmt.Errorf("read from TUN %s: %w", t.name, err)
	}
	return n, nil
}

// WritePacket writes a raw IP packet into the TUN interface.
func (t *LinuxTun) WritePacket(pkt []byte) error {
	if t.file == nil {
		return fmt.Errorf("WritePacket called but TUN file is nil for %s", t.name)
	}

	_, err := syscall.Write(int(t.file.Fd()), pkt)
	if err != nil {
		return fmt.Errorf("write to TUN %s: %w", t.name, err)
	}
	return nil
}

// Close closes the underlying /dev/net/tun file descriptor.
// We do NOT delete the interface itself.
func (t *LinuxTun) Close() error {
	if t.file != nil {
		if err := t.file.Close(); err != nil {
			return err
		}
		log.Printf("[Tunnel][linux] Closed TUN fd for %s", t.name)
		t.file = nil
	} else {
		log.Printf("[Tunnel][linux] Close called on %s but file is nil", t.name)
	}
	return nil
}
