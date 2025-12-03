package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/shrutianand/zero-trust-gateway/internal/controlplane"
)

// main is the entry point for the control plane binary.
// It wires together the State, Server, and HTTPS server with mTLS.
func main() {
	// Flags for address and TLS config
	addr := flag.String("listen-addr", ":8443", "control plane listen address (HTTPS)")
	tlsCertFile := flag.String("tls-cert", "certs/cp.crt", "TLS server certificate file")
	tlsKeyFile := flag.String("tls-key", "certs/cp.key", "TLS server private key file")
	tlsClientCAFile := flag.String("tls-client-ca", "certs/ca.crt", "CA file for verifying client certificates")

	flag.Parse()

	// --- 1. Load policy config and initialize state ---

	const policyPath = "config/policy.json"
	policyCfg, err := controlplane.LoadPolicyConfig(policyPath)
	if err != nil {
		log.Printf("Failed to load policy config from file: %v", err)
		log.Printf("Falling back to default policy config")
		policyCfg = controlplane.DefaultPolicyConfig()
	}

	state := controlplane.NewState(policyCfg)

	// cpServer is your control-plane HTTP handler wrapper
	cpServer := controlplane.NewServer(state, policyPath)

	// --- 2. HTTP mux with all REST endpoints registered ---

	mux := http.NewServeMux()
	cpServer.RegisterHandlers(mux)

	// --- 3. Build TLS config for mTLS ---

	// Load server certificate + key (control-plane identity)
	cpCert, err := tls.LoadX509KeyPair(*tlsCertFile, *tlsKeyFile)
	if err != nil {
		log.Fatalf("failed to load server TLS key pair (%s, %s): %v",
			*tlsCertFile, *tlsKeyFile, err)
	}

	// Load CA cert(s) used to verify client certificates
	caPEM, err := os.ReadFile(*tlsClientCAFile)
	if err != nil {
		log.Fatalf("failed to read client CA file %s: %v", *tlsClientCAFile, err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("failed to append client CA certs from %s", *tlsClientCAFile)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cpCert},
		ClientCAs:    clientCAPool,
		// Require clients to present a valid certificate signed by our CA.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	// --- 4. Start HTTPS server with mTLS ---

	httpServer := &http.Server{
		Addr:      *addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Control plane listening on https://%s (mTLS required)", *addr)
	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("control-plane exited: %v", err)
	}
}
