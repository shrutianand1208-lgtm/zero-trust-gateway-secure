package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/shrutianand/zero-trust-gateway/internal/models"
)

type PolicyConfig map[string][]string

type State struct {
	mu             sync.RWMutex
	nodes          map[string]*models.Node
	tokens         map[string]string
	tagPolicies    PolicyConfig
	nextTunnelHost uint8 // host part for 100.64.0.X
}

// ListNodes returns a snapshot slice of all known nodes.
// The slice contains copies, so callers can't mutate internal state.
func (s *State) ListNodes() []*models.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodes := make([]*models.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		// Make a shallow copy so external code can't accidentally mutate our map entries.
		copyNode := *n
		nodes = append(nodes, &copyNode)
	}
	return nodes
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b) // 32-char random token
}

func (s *State) ValidateToken(nodeID, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expected, ok := s.tokens[nodeID]
	if !ok {
		return false
	}

	return expected == token
}

// NewState creates and returns a new, empty State.
func NewState(policyCfg PolicyConfig) *State {
	return &State{
		nodes:          make(map[string]*models.Node),
		tokens:         make(map[string]string),
		tagPolicies:    policyCfg,
		nextTunnelHost: 10,
	}
}

// RegisterNode is called when an agent sends a registration request.
// It saves/updates the node in our map.

func (s *State) RegisterNode(req *models.NodeRegistrationRequest) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token := generateToken()
	tunnelIP := s.allocateTunnelIPLocked()
	s.nodes[req.NodeID] = &models.Node{
		NodeID:   req.NodeID,
		IP:       req.IP,
		Tags:     req.Tags,
		LastSeen: time.Now().Unix(),
		Token:    token,
		TunnelIP: tunnelIP,
	}

	s.tokens[req.NodeID] = token
	return token, tunnelIP
}

// UpdateHeartbeat is called when an agent sends a heartbeat.
// We just refresh the LastSeen timestamp.
func (s *State) UpdateHeartbeat(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n, ok := s.nodes[nodeID]; ok {
		n.LastSeen = time.Now().Unix()
	}
}

// allowedCIDRsForTags returns the union of CIDR ranges allowed for the given tags.
// This is a simple, hard-coded policy engine for now.
// Later, this could come from a config file or database.
func (s *State) AllowedCIDRsForTags(tags []string) []string {

	// Use a map to avoid duplicates when multiple tags map to same CIDR.
	cidrSet := make(map[string]struct{})

	for _, tag := range tags {
		if cidrs, ok := s.tagPolicies[tag]; ok {
			for _, c := range cidrs {
				cidrSet[c] = struct{}{}
			}
		}
	}

	// Build slice from set
	result := make([]string, 0, len(cidrSet))
	for c := range cidrSet {
		result = append(result, c)
	}

	// If no tags matched, you can decide:
	// - return empty (deny all), or
	// - return some default CIDRs.
	// For now, we will *deny all* if no tags matched.
	return result
}

// GetPolicy returns the policy for a given node ID.
// Right now it's a simple hardcoded policy.
func (s *State) GetPolicy(nodeID string) *models.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If the node doesn't exist, return nil.
	node, ok := s.nodes[nodeID]
	if !ok {
		return nil
	}

	allowed := s.AllowedCIDRsForTags(node.Tags)

	// For now, everyone gets the same allowed CIDR.
	return &models.Policy{
		NodeID:       nodeID,
		AllowedCIDRs: allowed,
	}
}

// DefaultPolicyConfig returns a simple built-in mapping if no file is provided.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		"dev":   {"10.0.0.0/24"},
		"prod":  {"10.1.0.0/24"},
		"admin": {"10.255.0.0/24"},
	}
}

// LoadPolicyConfig loads policy config from a JSON file.
// If anything goes wrong, caller can fall back to DefaultPolicyConfig.
func LoadPolicyConfig(path string) (PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg PolicyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (s *State) GetNode(nodeID string) *models.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nodes[nodeID]
	if !ok {
		return nil
	}

	// Return a copy so callers can't mutate internal state.
	copy := *n
	return &copy
}

func (s *State) UpdatePolicyConfig(cfg PolicyConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tagPolicies = cfg
}

func (s *State) allocateTunnelIPLocked() string {
	// NOTE: caller must hold s.mu
	if s.nextTunnelHost == 0 {
		s.nextTunnelHost = 10
	}
	ip := fmt.Sprintf("100.64.0.%d", s.nextTunnelHost)
	s.nextTunnelHost++
	return ip
}
