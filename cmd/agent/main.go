package main

import (
	"flag"
	"log"
	"strings"

	"github.com/shrutianand/zero-trust-gateway/internal/agent"
)

func main() {
	nodeID := flag.String("node-id", "node-1", "unique id for this node")
	ip := flag.String("ip", "10.0.0.1", "IP address of this node")
	tagsStr := flag.String("tags", "dev", "comma-separated tags (e.g. dev,web)")
	cpURL := flag.String("cp-url", "http://localhost:8080", "control plane base URL")
	routeMode := flag.String("route-mode", "logging", "route mode: logging or linux")
	tunnelName := flag.String("tunnel-name", "tun0", "tunnel interface name (e.g. tun0, ztgw0)")
	overlayListen := flag.String("overlay-listen", ":4000", "UDP listen address for overlay (e.g. :4000)")
	peerTunnelIP := flag.String("peer-tun-ip", "", "peer tunnel IP (e.g. 100.64.0.11)")
	peerEndpoint := flag.String("peer-endpoint", "", "peer UDP endpoint host:port (e.g. 10.0.2.16:4000)")
	tlsEnable := flag.Bool("tls-enable", true, "enable TLS (HTTPS) to control plane")
	tlsCACert := flag.String("tls-ca-cert", "certs/ca.crt", "CA certificate file to verify control plane")
	tlsClientCert := flag.String("tls-client-cert", "certs/agent.crt", "client certificate for mTLS")
	tlsClientKey := flag.String("tls-client-key", "certs/agent.key", "client key for mTLS")
	tlsInsecure := flag.Bool("tls-insecure-skip-verify", false, "skip server TLS certificate verification (DEV ONLY)")

	flag.Parse()

	var tags []string
	if *tagsStr != "" {
		tags = strings.Split(*tagsStr, ",")
	}

	cfg := agent.Config{
		NodeID:                *nodeID,
		IP:                    *ip,
		Tags:                  tags,
		CPURL:                 *cpURL,
		TunnelName:            *tunnelName,
		RouteMode:             *routeMode,
		OverlayListen:         *overlayListen,
		TLSEnable:             *tlsEnable,
		TLSCACertFile:         *tlsCACert,
		TLSClientCertFile:     *tlsClientCert,
		TLSClientKeyFile:      *tlsClientKey,
		TLSInsecureSkipVerify: *tlsInsecure,
	}

	if *peerTunnelIP != "" && *peerEndpoint != "" {
		cfg.Peers = append(cfg.Peers, agent.PeerConfig{
			TunnelIP: *peerTunnelIP,
			Endpoint: *peerEndpoint,
		})
	}

	// Choose route manager implementation based on routeMode.
	var rm agent.RouteManager
	switch *routeMode {
	case "linux":
		rm = agent.NewLinuxRouteManager()
		log.Printf("[Agent %s] Using LinuxRouteManager for data plane", cfg.NodeID)
	default:
		rm = agent.NewLoggingRouteManager()
		log.Printf("[Agent %s] Using LoggingRouteManager for data plane", cfg.NodeID)
	}

	a := agent.NewAgent(cfg, rm)
	log.Printf("[Agent %s] Starting with IP=%s, tags=%v, cp=%s, routeMode=%s, tunnel=%s\n",
		cfg.NodeID, cfg.IP, cfg.Tags, cfg.CPURL, *routeMode, *tunnelName)

	if err := a.Run(); err != nil {
		log.Fatalf("agent exited with error: %v", err)
	}
}
