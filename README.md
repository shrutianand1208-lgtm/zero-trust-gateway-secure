🚀 Zero Trust Gateway (Secure)

A minimalist Zero Trust overlay network written in Go

This project demonstrates core cloud & networking concepts:

Control-plane / data-plane separation

mTLS authentication with a custom CA

Dynamic policy distribution

Linux TUN interfaces

Routing + firewall automation

Heartbeats, node registry, health status

UDP-based overlay transport

Raw IP packet forwarding

Secure system design patterns

It is built as a learning project for systems, networking, and security engineering.

🧱 Architecture Overview

                   +-----------------------------+
                   |        Control Plane        |
                   |-----------------------------|
HTTPS + mTLS  ---> | /register (issue token +    |
                   |             allocate tun IP)|
HTTPS + mTLS  ---> | /policy (CIDR allow list)   |
HTTPS + mTLS  ---> | /heartbeat                  |
HTTPS + mTLS  ---> | /nodes (debug view)         |
                   +--------------+--------------+
                                  |
                HTTPS/mTLS Secure Control Channel
                                  |
     -----------------------------------------------------------------
     |                                                               |
+------------+                                            +------------+
|   Agent A  |                                            |   Agent B  |
|------------|                                            |------------|
| Linux TUN interface (ztgwa)                             | Linux TUN (ztgwb)
| Tunnel IP: 100.64.0.10                                   | Tunnel IP: 100.64.0.11
| Programs routes:                                          | Programs routes:
|   ip route replace <cidr> dev ztgwa                      |   ip route replace <cidr> dev ztgwb
| Firewall rules (iptables)                                | Firewall rules
| Heartbeat → CP                                           | Heartbeat → CP
| Overlay UDP reader/writer                                | Overlay UDP reader/writer
| TUN ↔ Overlay packet bridge                              | TUN ↔ Overlay packet bridge
+------------+                                            +------------+


✨ Features Implemented
🔐 Zero Trust Control Plane

Full mTLS (client certificates required)

Custom Certificate Authority

Secure registration issuing:

Auth token

Tunnel IP (100.64.0.x)

Dynamic CIDR policy engine (config/policy.json)

Heartbeats + last_seen + online/offline status

/nodes endpoint showing:

  IP, tags, last_seen, status

  tunnel IP

  masked token

  allowed CIDRs

🖥️ Linux Agent (Data Plane)

Communicates via HTTPS + mTLS

Creates Linux TUN interface:

Opens /dev/net/tun

Uses TUNSETIFF

Assigns tunnel IP (/32)

Brings interface up

Programs routes:

ip route replace <cidr> dev <tun>


Programs firewall:

iptables -A OUTPUT -d <cidr> -j ACCEPT


Runs:

Heartbeat loop

Policy refresh loop

TUN read loop

Overlay UDP listener

Packet forwarding to peers (if configured)

🌐 Overlay Network

TUN packets forwarded via UDP overlay socket

Linux kernel → TUN → Agent → UDP → Peer

Peer → UDP → Agent → TUN → Kernel

Currently unencrypted overlay (Phase 7.3 adds AEAD).

🗂 Directory Structure
zero-trust-gateway-secure/
  ├── cmd/
  │   ├── control-plane/     # Control plane binary
  │   └── agent/             # Agent binary
  ├── internal/
  │   ├── controlplane/      # HTTP handlers, registry, policy engine
  │   ├── agent/             # TUN, overlay, TLS client config
  │   └── models/            # Shared structs
  ├── config/
  │   └── policy.json
  ├── certs/                 # Certificates (public only)
  ├── README.md
  ├── go.mod
  └── .gitignore

🔐 Certificate Structure & Security

Your PKI has:

certs/ca.crt — CA certificate

certs/ca.key — NOT in git

certs/cp.crt — control-plane cert

certs/cp.key — NOT in git

certs/agent.crt — agent cert

certs/agent.key — NOT in git

Your .gitignore must contain:

certs/*.key
certs/*.csr
certs/*.srl


🚀 Running the System (Full Flow)
1️⃣ Start Control Plane (Mac)
go run ./cmd/control-plane \
  --listen-addr=":8443" \
  --tls-cert="certs/cp.crt" \
  --tls-key="certs/cp.key" \
  --tls-client-ca="certs/ca.crt"


Expected output:

Control plane listening on https://:8443 (mTLS required)

2️⃣ Test CP Health with mTLS
curl --cacert certs/ca.crt \
     --cert certs/agent.crt \
     --key certs/agent.key \
     https://localhost:8443/health

3️⃣ Start Agent (Linux VM)
sudo /usr/local/go/bin/go run ./cmd/agent \
  --node-id=node-a \
  --ip=10.250.0.10 \
  --tags=dev \
  --route-mode=linux \
  --tunnel-name=ztgwa \
  --overlay-listen=":4000" \
  --cp-url="https://<mac-ip>:8443" \
  --tls-enable=true \
  --tls-ca-cert="certs/ca.crt" \
  --tls-client-cert="certs/agent.crt" \
  --tls-client-key="certs/agent.key"


Expected:

Registered successfully, tunnel_ip=100.64.0.10
TUN ztgwa created and brought up
Assigned 100.64.0.10/32
Applying policy...
Overlay listener started
Heartbeat OK

4️⃣ Check Node State

From Mac:

curl --cacert certs/ca.crt \
     --cert certs/agent.crt \
     --key certs/agent.key \
     https://localhost:8443/nodes | jq

5️⃣ Validate Linux Network State
ip addr show ztgwa
ip route | grep 10.42.0.0
iptables -S OUTPUT | grep 10.42

6️⃣ Test TUN RX Flow

Ping any IP inside allowed CIDR:

ping -c 1 10.42.0.5


Agent log should show:

TUN read 84 bytes

📌 Future Extensions

These are optional, but great to implement:

🔐 1. Encrypted overlay (AEAD)

ChaCha20-Poly1305 or AES-GCM

Key exchange (Noise IK or WireGuard-style)

🌎 2. Multi-node peer discovery

Gossip or CP-managed peer list

Mesh building

🧭 3. Multi-hop routing

Forward packets based on tunnel IP prefix

🌐 4. NAT traversal

STUN + UDP hole punching

🗄 5. Persistent control-plane datastore

SQLite or Postgres
