# Zero Trust Gateway (In Progress)

A lightweight **Zero Trust networking system** 

This project implements:

- A **Control Plane**  
  - Node registration  
  - Token issuance  
  - Policy distribution  
  - Heartbeat tracking  

- An **Agent**  
  - Registers with Control Plane  
  - Fetches Allowed CIDR policies  
  - Applies routing + firewall logic (currently simulated)  
  - Authenticates using Bearer tokens  
  - Maintains heartbeat  
  - Has a clean **Tunnel abstraction** for future overlay networking  

This is an **ongoing project**, and more features (real tunnels, `ip route`, `iptables`,
encryption, multi-node mesh, multi-cloud support) will be added soon.

---

## Directory Structure

```text
zero-trust-gateway/
  ├── cmd/
  │   ├── control-plane/   # Control plane entrypoint
  │   └── agent/           # Agent entrypoint
  ├── internal/
  │   ├── controlplane/    # CP logic (state, handlers)
  │   ├── agent/           # Agent logic (policy, heartbeat, tunnel)
  │   └── models/          # Shared data types
  └── README.md
