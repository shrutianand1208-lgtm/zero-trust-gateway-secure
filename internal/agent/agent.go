package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shrutianand/zero-trust-gateway/internal/models"
)

// RouteManager is responsible for applying network policy (routes, firewall, etc.)
// for a given node. The Agent will delegate data-plane changes to this component.
type RouteManager interface {
	ApplyPolicy(nodeID string, policy *models.Policy, tunnelName string) error
}

// LoggingRouteManager is a simple implementation of RouteManager that only logs
// what it *would* do. This is useful for development, macOS, or dry-run mode.
type LoggingRouteManager struct{}

// LinuxRouteManager is intended to apply policy using real Linux networking
// primitives (ip route, iptables, etc.). For now, it only logs what it would do,
// and warns if used on non-Linux systems.
type LinuxRouteManager struct{}

type PeerConfig struct {
	TunnelIP string // e.g. "100.64.0.11"
	Endpoint string // e.g. "10.0.2.16:4000"
}

// Config holds configuration for the agent instance.
type Config struct {
	NodeID        string
	IP            string
	Tags          []string
	CPURL         string // Control plane base URL, e.g. "http://localhost:8080"
	TunnelName    string
	RouteMode     string // "logging" or "linux"
	OverlayListen string
	Peers         []PeerConfig
	// TLS / mTLS
	TLSEnable             bool
	TLSCACertFile         string
	TLSClientCertFile     string
	TLSClientKeyFile      string
	TLSInsecureSkipVerify bool
}

// Agent represents a running agent process.
type Agent struct {
	cfg           Config
	httpClient    *http.Client
	token         string
	tunnel        Tunnel
	routeMgr      RouteManager
	lastPolicyKey string // simple fingerprint of last applied policy
	tunnelIP      string
	overlayConn   *net.UDPConn
}

func NewLoggingRouteManager() *LoggingRouteManager {
	return &LoggingRouteManager{}
}

func NewLinuxRouteManager() *LinuxRouteManager {
	return &LinuxRouteManager{}
}

func (l *LinuxRouteManager) ApplyPolicy(nodeID string, policy *models.Policy, tunnelName string) error {
	if runtime.GOOS != "linux" {
		log.Printf("[RouteMgr][linux] WARNING: linux route mode selected but running on %s; doing no-op",
			runtime.GOOS)
		return nil
	}

	if policy == nil {
		log.Printf("[RouteMgr][linux] policy is nil for node=%s; nothing to apply", nodeID)
		return nil
	}

	if tunnelName == "" {
		tunnelName = "UNKNOWN"
	}

	log.Printf("[RouteMgr][linux] Applying policy for node=%s via tunnel=%s", nodeID, tunnelName)

	// In a real Linux implementation, typical steps:
	// 1) Ensure the tunnel interface exists and is up (done elsewhere)
	// 2) Add routes for each AllowedCIDR
	// 3) Configure firewall rules for those CIDRs

	for _, cidr := range policy.AllowedCIDRs {
		// ip route: add/replace route for CIDR via tunnel
		routeCmd := exec.Command("ip", "route", "replace", cidr, "dev", tunnelName)
		log.Printf("[RouteMgr][linux] Running: %s", routeCmd.String())
		if output, err := routeCmd.CombinedOutput(); err != nil {
			log.Printf("[RouteMgr][linux] ERROR running ip route for %s: %v, output=%s",
				cidr, err, string(output))
		}

		// iptables: allow traffic to that CIDR
		allowCmd := exec.Command("iptables", "-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT")
		log.Printf("[RouteMgr][linux] Running: %s", allowCmd.String())
		if output, err := allowCmd.CombinedOutput(); err != nil {
			log.Printf("[RouteMgr][linux] ERROR running iptables allow for %s: %v, output=%s",
				cidr, err, string(output))
		}

	}

	// Optionally, could add a "default deny" rule here, e.g.:
	// denyCmd := []string{"iptables", "-A", "OUTPUT", "-j", "DROP"}
	// log.Printf("[RouteMgr][linux] Would run: %v", denyCmd)

	// TODO (later, on real Linux):
	// - Use os/exec.Command(...) to actually execute the above commands.
	// - Handle errors and idempotency (routes that already exist, etc.)

	return nil
}

func (l *LoggingRouteManager) ApplyPolicy(nodeID string, policy *models.Policy, tunnelName string) error {
	if tunnelName == "" {
		tunnelName = "UNKNOWN"
	}

	log.Printf("[RouteMgr] Applying policy for node=%s via tunnel=%s", nodeID, tunnelName)

	for _, cidr := range policy.AllowedCIDRs {
		log.Printf("[RouteMgr] Would add route: ip route add %s dev %s", cidr, tunnelName)
		log.Printf("[RouteMgr] Would allow traffic to CIDR: %s (e.g., iptables -A OUTPUT -d %s -j ACCEPT)",
			cidr, cidr)
	}

	return nil
}

func buildHTTPClient(cfg Config) *http.Client {
	if !cfg.TLSEnable {
		log.Printf("[Agent %s] TLS disabled; using plain HTTP client", cfg.NodeID)
		return &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	// 1. Load CA cert to verify control-plane server cert
	caCertPEM, err := os.ReadFile(cfg.TLSCACertFile)
	if err != nil {
		log.Fatalf("[Agent %s] failed to read CA cert file %s: %v",
			cfg.NodeID, cfg.TLSCACertFile, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("[Agent %s] failed to append CA certs", cfg.NodeID)
	}

	// 2. Load client cert for mTLS
	clientCert, err := tls.LoadX509KeyPair(cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
	if err != nil {
		log.Fatalf("[Agent %s] failed to load client key pair (%s, %s): %v",
			cfg.NodeID, cfg.TLSClientCertFile, cfg.TLSClientKeyFile, err)
	}

	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify, // false in real setups
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
}

// NewAgent constructs a new Agent with the given config.
func NewAgent(cfg Config, rm RouteManager) *Agent {
	if rm == nil {
		rm = NewLoggingRouteManager()
	}

	tunnelName := cfg.TunnelName
	if tunnelName == "" {
		tunnelName = "tun0"
	}

	var tun Tunnel

	// Decide which Tunnel implementation to use.
	if cfg.RouteMode == "linux" && runtime.GOOS == "linux" {
		lt, err := NewLinuxTun(tunnelName)
		if err != nil {
			log.Printf("[Agent %s] ERROR creating LinuxTun: %v, falling back to LoggingTunnel", cfg.NodeID, err)
			tun = NewLoggingTunnel(tunnelName)
		} else {
			log.Printf("[Agent %s] Using LinuxTun(%s) for tunnel", cfg.NodeID, tunnelName)
			tun = lt
		}
	} else {
		log.Printf("[Agent %s] Using LoggingTunnel(%s) for tunnel (routeMode=%s, GOOS=%s)",
			cfg.NodeID, tunnelName, cfg.RouteMode, runtime.GOOS)
		tun = NewLoggingTunnel(tunnelName)
	}

	return &Agent{
		cfg:        cfg,
		httpClient: buildHTTPClient(cfg),
		tunnel:     tun,
		routeMgr:   rm,
	}
}

func (a *Agent) register() error {
	reqBody := models.NodeRegistrationRequest{
		NodeID: a.cfg.NodeID,
		IP:     a.cfg.IP,
		Tags:   a.cfg.Tags,
	}

	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := a.cfg.CPURL + "/register"
	log.Printf("[Agent %s] Registering with %s\n", a.cfg.NodeID, url)

	resp, err := a.httpClient.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status from /register: %s", resp.Status)
	}

	// Parse the JSON response: { "token": "..." }
	var respBody struct {
		Token    string `json:"token"`
		TunnelIP string `json:"tunnel_ip"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}

	if respBody.Token == "" {
		return fmt.Errorf("empty token in register response")
	}

	a.token = respBody.Token
	a.tunnelIP = respBody.TunnelIP
	log.Printf("[Agent %s] Registered successfully, got token: %s, tunnel_ip=%s\n",
		a.cfg.NodeID, a.token, a.tunnelIP)
	return nil
}

func policyKey(p *models.Policy) string {
	if p == nil {
		return ""
	}

	// Make a copy so we don't mutate the original slice.
	cidrs := append([]string(nil), p.AllowedCIDRs...)
	sort.Strings(cidrs)

	return strings.Join(cidrs, ",")
}

func (a *Agent) fetchPolicy() error {
	url := fmt.Sprintf("%s/policy?node_id=%s", a.cfg.CPURL, a.cfg.NodeID)
	log.Printf("[Agent %s] Fetching policy from %s\n", a.cfg.NodeID, url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	// Add Authorization header with the token
	req.Header.Set("Authorization", "Bearer "+a.token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from /policy: %s", resp.Status)
	}

	var policy models.Policy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return err
	}

	log.Printf("[Agent %s] Received policy: %+v\n", a.cfg.NodeID, policy)

	newKey := policyKey(&policy)
	if newKey == a.lastPolicyKey {
		log.Printf("[Agent %s] Policy unchanged, skipping apply", a.cfg.NodeID)
		return nil
	}

	// Apply routes/firewall here.
	if err := a.applyPolicy(&policy); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	a.lastPolicyKey = newKey
	return nil
}

func (a *Agent) startPolicyLoop() {
	ticker := time.NewTicker(30 * time.Second) // refresh every 30s for now
	defer ticker.Stop()

	for range ticker.C {
		if err := a.fetchPolicy(); err != nil {
			log.Printf("[Agent %s] Policy refresh error: %v\n", a.cfg.NodeID, err)
		}
	}
}

func (a *Agent) startHeartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := a.sendHeartbeat(); err != nil {
			log.Printf("[Agent %s] Heartbeat error: %v\n", a.cfg.NodeID, err)
		}
	}
}

func (a *Agent) sendHeartbeat() error {
	hb := models.HeartbeatRequest{NodeID: a.cfg.NodeID}
	buf, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	url := a.cfg.CPURL + "/heartbeat"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from /heartbeat: %s", resp.Status)
	}

	log.Printf("[Agent %s] Heartbeat OK\n", a.cfg.NodeID)
	return nil
}

// applyPolicy is where the agent enforces the policy it received from the control plane.
// For now, we are only LOGGING what we *would* do on a real Linux machine.
// Later, on Linux, we will replace this with real `ip route` and `iptables` commands.
func (a *Agent) applyPolicy(policy *models.Policy) error {
	log.Printf("[Agent %s] Applying policy for node %s", a.cfg.NodeID, policy.NodeID)

	// In a real system, you might:
	// 1. Set up a tunnel interface (e.g., wg0, tun0)
	// 2. Add routes pointing to that tunnel
	// 3. Configure firewall rules (iptables/nftables)

	if a.tunnel == nil {
		// In future, this would be an error: tunnel must be set up first.
		log.Printf("[Agent %s] WARNING: no tunnel configured; cannot apply routes realistically", a.cfg.NodeID)
	}

	// For now, we just log the intended actions.
	tunnelName := "" // placeholder name for a future tunnel device
	if a.tunnel != nil {
		tunnelName = a.tunnel.Name()
	}

	if a.routeMgr == nil {
		log.Printf("[Agent %s] ERROR: no RouteManager configured", a.cfg.NodeID)
		return nil // or return an error if you want to be strict
	}

	if err := a.routeMgr.ApplyPolicy(a.cfg.NodeID, policy, tunnelName); err != nil {
		return err
	}

	return nil
}

// startOverlayListener starts a UDP listener for overlay traffic.
// For now, it only logs incoming packets.
func (a *Agent) startOverlayListener() error {
	if a.cfg.OverlayListen == "" {
		log.Printf("[Agent %s] No overlay listen address configured; skipping overlay listener", a.cfg.NodeID)
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", a.cfg.OverlayListen)
	if err != nil {
		return fmt.Errorf("resolve overlay listen addr %q: %w", a.cfg.OverlayListen, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp on %q: %w", a.cfg.OverlayListen, err)
	}

	a.overlayConn = conn
	log.Printf("[Agent %s] Overlay listener started on %s", a.cfg.NodeID, conn.LocalAddr().String())

	// Simple goroutine to log received data.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[Agent %s] Overlay listener error: %v", a.cfg.NodeID, err)
				return
			}

			if n == 0 {
				continue
			}

			log.Printf("[Agent %s] Overlay received %d bytes from %s", a.cfg.NodeID, n, remote.String())

			if a.tunnel == nil {
				log.Printf("[Agent %s] No tunnel configured; dropping overlay packet", a.cfg.NodeID)
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			// Write the packet into the TUN interface.
			if err := a.tunnel.WritePacket(pkt); err != nil {
				log.Printf("[Agent %s] TUN write error: %v", a.cfg.NodeID, err)
				continue
			}

			log.Printf("[Agent %s] Injected %d bytes from overlay into TUN %s", a.cfg.NodeID, n, a.tunnel.Name())
		}
	}()

	return nil
}

// startTunReadLoop starts a goroutine that continuously reads packets
// from the TUN interface and (in future) forwards them to peers.
func (a *Agent) startTunReadLoop() {
	if a.tunnel == nil {
		log.Printf("[Agent %s] No tunnel configured; skipping TUN read loop", a.cfg.NodeID)
		return
	}

	if len(a.cfg.Peers) == 0 {
		log.Printf("[Agent %s] No peers configured; TUN read loop will only log packets", a.cfg.NodeID)
	}

	go func() {
		buf := make([]byte, 65535)

		for {
			n, err := a.tunnel.ReadPacket(buf)
			if err != nil {
				log.Printf("[Agent %s] TUN read error: %v", a.cfg.NodeID, err)
				return
			}
			if n == 0 {
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			log.Printf("[Agent %s] TUN read %d bytes", a.cfg.NodeID, n)

			if len(a.cfg.Peers) == 0 {
				continue
			}

			peer := a.cfg.Peers[0]
			if err := a.sendToPeer(peer.TunnelIP, pkt); err != nil {
				log.Printf("[Agent %s] sendToPeer error: %v",
					a.cfg.NodeID, err)
			}
		}
	}()
}

// sendToPeer sends raw bytes to a peer identified by its tunnel IP.
func (a *Agent) sendToPeer(peerTunnelIP string, payload []byte) error {
	if a.overlayConn == nil {
		return fmt.Errorf("overlayConn is nil; listener not started")
	}

	var endpoint string
	for _, p := range a.cfg.Peers {
		if p.TunnelIP == peerTunnelIP {
			endpoint = p.Endpoint
			break
		}
	}
	if endpoint == "" {
		return fmt.Errorf("no peer endpoint configured for tunnel IP %s", peerTunnelIP)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("resolve peer endpoint %q: %w", endpoint, err)
	}

	n, err := a.overlayConn.WriteToUDP(payload, udpAddr)
	if err != nil {
		return fmt.Errorf("write to peer %s (%s): %w", peerTunnelIP, endpoint, err)
	}

	log.Printf("[Agent %s] Overlay sent %d bytes to peer %s (%s)",
		a.cfg.NodeID, n, peerTunnelIP, endpoint)
	return nil
}

// Run is the main entry point for the agent:
// 1. Register with the control plane
// 2. Fetch policy
// 3. Start sending heartbeats periodically
func (a *Agent) Run() error {
	// 1. Register first, so we get token + tunnel IP.
	if err := a.register(); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	// 2. Bring up tunnel and assign tunnel IP (if any).
	if a.tunnel != nil {
		if err := a.tunnel.Up(); err != nil {
			return fmt.Errorf("tunnel up: %w", err)
		}

		if a.tunnelIP != "" {
			cidr := a.tunnelIP + "/32"
			if err := a.tunnel.SetAddress(cidr); err != nil {
				return fmt.Errorf("tunnel set address: %w", err)
			}
		} else {
			log.Printf("[Agent %s] WARNING: no tunnel IP from control plane; skipping SetAddress", a.cfg.NodeID)
		}
	}

	// 3. Fetch and apply policy.
	if err := a.fetchPolicy(); err != nil {
		return fmt.Errorf("fetch policy: %w", err)
	}

	// 4. Start overlay listener (UDP)
	if err := a.startOverlayListener(); err != nil {
		log.Printf("[Agent %s] ERROR starting overlay listener: %v", a.cfg.NodeID, err)
		// not fatal for now
	}

	a.startTunReadLoop()
	// 5. Background loops.
	go a.startHeartbeatLoop()
	go a.startPolicyLoop()

	select {}
}
