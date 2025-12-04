# 🚀 Zero Trust Gateway (Secure)

A minimalist **Zero Trust overlay network** written in Go — inspired by Tailscale, ZeroTier, BeyondCorp, and Aviatrix.

This project demonstrates:

- Control-plane / data-plane separation  
- **mTLS authentication** with custom CA  
- Dynamic policies  
- Linux **TUN interfaces**  
- Routing & firewall automation  
- UDP overlay network  
- Raw IP packet forwarding  
- Distributed systems concepts  

---

## 🧱 Architecture Overview

```
                   +-----------------------------+
                   |        Control Plane        |
                   |-----------------------------|
HTTPS + mTLS  ---> | /register (alloc tunnel IP) |
HTTPS + mTLS  ---> | /policy (CIDR allow list)   |
HTTPS + mTLS  ---> | /heartbeat                  |
HTTPS + mTLS  ---> | /nodes (debug view)         |
                   +--------------+--------------+
                                  |
                      Secure HTTPS/mTLS channel
                                  |
     -----------------------------------------------------------------
     |                                                               |
+------------+                                            +------------+
|   Agent A  |                                            |   Agent B  |
|------------|                                            |------------|
| Linux TUN (ztgwa)                                       | Linux TUN (ztgwb)
| Tunnel: 100.64.0.10                                     | Tunnel: 100.64.0.11
| Routes via TUN                                          | Routes via TUN
| iptables rules                                           | iptables rules
| Heartbeat → CP                                           | Heartbeat → CP
| UDP overlay                                              | UDP overlay
| TUN ↔ UDP packet bridge                                  | TUN ↔ UDP packet bridge
+------------+                                            +------------+
```

---

# ✨ Features

### 🔐 Control Plane
- Full mTLS (mutual TLS)
- Token generation
- Automatic tunnel IP allocation (`100.64.0.x`)
- Dynamic CIDR policy distribution
- Heartbeat health tracking
- `/nodes` endpoint for debugging

---

### 🖥️ Agent (Linux Data Plane)
- HTTPS + mTLS communication
- Creates Linux TUN interface:
  - `/dev/net/tun`
  - `TUNSETIFF`
  - `ip link set up`
  - `ip addr add`
- Installs routes:
  ```bash
  ip route replace <cidr> dev <tun>
  ```
- Installs firewall rules:
  ```bash
  iptables -A OUTPUT -d <cidr> -j ACCEPT
  ```
- UDP overlay packet forwarding

---

# 🗂 Directory Structure

```
zero-trust-gateway-secure/
  ├── cmd/
  │   ├── control-plane/
  │   └── agent/
  ├── internal/
  │   ├── controlplane/
  │   ├── agent/
  │   └── models/
  ├── config/
  │   └── policy.json
  ├── certs/
  ├── go.mod
  ├── go.sum
  ├── .gitignore
  └── README.md
```

---

# 🔐 Certificates & Security

Private keys are **ignored** via `.gitignore`:

```
certs/*.key
certs/*.csr
certs/*.srl
```

Committed files (safe):

- `certs/ca.crt`
- `certs/cp.crt`
- `certs/agent.crt`

---

# 🚀 Running the Control Plane

Run on macOS:

```bash
go run ./cmd/control-plane \
  --listen-addr=":8443" \
  --tls-cert="certs/cp.crt" \
  --tls-key="certs/cp.key" \
  --tls-client-ca="certs/ca.crt"
```

Expected:

```
Control plane listening on https://:8443 (mTLS required)
```

---

# 🧪 Test Control Plane with curl (mTLS)

```bash
curl --cacert certs/ca.crt \
     --cert certs/agent.crt \
     --key certs/agent.key \
     https://localhost:8443/health
```

---

# 🤖 Running the Agent (Linux VM)

```bash
sudo /usr/local/go/bin/go run ./cmd/agent \
  --node-id=node-a \
  --ip=10.250.0.10 \
  --tags=dev \
  --route-mode=linux \
  --tunnel-name=ztgwa \
  --overlay-listen=":4000" \
  --cp-url="https://<MAC-IP>:8443" \
  --tls-enable=true \
  --tls-ca-cert="certs/ca.crt" \
  --tls-client-cert="certs/agent.crt" \
  --tls-client-key="certs/agent.key"
```

Expected logs:

```
Registered successfully, tunnel_ip=100.64.0.10
TUN created and up
Policy applied
Overlay listener started
Heartbeat OK
```

---

# 🔍 Inspect Nodes (Mac)

```bash
curl --cacert certs/ca.crt \
     --cert certs/agent.crt \
     --key certs/agent.key \
     https://localhost:8443/nodes | jq
```

---

# 🧪 Validate TUN Interface (Linux)

```bash
ip addr show ztgwa
ip route | grep 10.42
iptables -S OUTPUT | grep 10.42
```

---

# 📌 Future Enhancements
- Encrypted overlay (AES-GCM / ChaCha20)
- Peer auto-discovery
- STUN-based NAT traversal
- Multi-hop routing
- Persisting nodes in DB
- Web dashboard

---
