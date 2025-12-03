package models

// NodeRegistrationRequest is what an agent sends to the control plane
// the first time it wants to join the network.
type NodeRegistrationRequest struct {
	NodeID string   `json:"node_id"`
	IP     string   `json:"ip"`
	Tags   []string `json:"tags"`
}

// Node represents how the control plane stores information
// about each registered node.
type Node struct {
	NodeID   string   `json:"node_id"`
	IP       string   `json:"ip"`
	Tags     []string `json:"tags"`
	LastSeen int64    `json:"last_seen_unix"` // Unix time when we last got a heartbeat
	Token    string   `json:"token"`
	TunnelIP string   `json:"tunnel_ip,omitempty"`
}

// Policy is what the control plane sends back to the agent.
// For now it's very simple: "you are allowed to reach these CIDR ranges".
type Policy struct {
	NodeID       string   `json:"node_id"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
}

// HeartbeatRequest is what the agent sends periodically
// to say "I'm alive".
type HeartbeatRequest struct {
	NodeID string `json:"node_id"`
}

// NodeRegistrationResponse is what the control plane sends back
// to an agent after successful registration.
type NodeRegistrationResponse struct {
	Token    string `json:"token"`
	TunnelIP string `json:"tunnel_ip"`
}
