package controlplane

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/shrutianand/zero-trust-gateway/internal/models"
)

// Server wraps the State and exposes HTTP handlers.
// It knows *how* to talk HTTP, and delegates business logic to State.
type Server struct {
	state            *State
	policyConfigPath string
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	// Expect format: "Bearer <token>"
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return ""
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// NewServer constructs a Server with the given State.
func NewServer(state *State, policyPath string) *Server {
	return &Server{
		state:            state,
		policyConfigPath: policyPath,
	}
}

// RegisterHandlers attaches all HTTP routes to the given ServeMux.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.HandleFunc("/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/nodes", s.handleNodes)
	mux.HandleFunc("/nodes/html", s.handleNodesHTML)
	mux.HandleFunc("/policy/preview", s.handlePolicyPreview)
	mux.HandleFunc("/node/", s.handleNode)
	mux.HandleFunc("/admin/reload-policy", s.handleReloadPolicy)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleRegister receives a NodeRegistrationRequest from an agent.
// It decodes JSON, calls State.RegisterNode, and returns 201 Created.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.NodeRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("[CP] Registering node: %+v\n", req)
	token, tunnelIP := s.state.RegisterNode(&req)

	// Build a small response object
	resp := models.NodeRegistrationResponse{
		Token:    token,
		TunnelIP: tunnelIP,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

}

// handlePolicy returns the Policy for a given node_id.
// URL: /policy?node_id=node-1
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "missing node_id", http.StatusBadRequest)
		return
	}

	token := extractBearerToken(r)
	if token == "" || !s.state.ValidateToken(nodeID, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	policy := s.state.GetPolicy(nodeID)
	if policy == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policy); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

// handleHeartbeat updates LastSeen for the node.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var hb models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token := extractBearerToken(r)
	if token == "" || !s.state.ValidateToken(hb.NodeID, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("[CP] Heartbeat from node: %s\n", hb.NodeID)
	s.state.UpdateHeartbeat(hb.NodeID)

	w.WriteHeader(http.StatusOK)
}

// handleNodes returns a list of all registered nodes.
// In a real system you'd likely protect this with admin auth / mTLS.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes := s.state.ListNodes()
	now := time.Now().Unix()

	// nodeView is what we actually return to callers of /nodes.
	type nodeView struct {
		NodeID      string   `json:"node_id"`
		IP          string   `json:"ip"`
		Tags        []string `json:"tags"`
		LastSeen    int64    `json:"last_seen_unix"`
		Status      string   `json:"status"`       // healthy / stale / offline
		TokenMasked string   `json:"token_masked"` // don't leak full token
		TunnelIP    string   `json:"tunnel_ip,omitempty"`
	}

	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		age := now - n.LastSeen
		status := "offline"
		switch {
		case age <= 20:
			status = "healthy"
		case age <= 60:
			status = "stale"
		default:
			status = "offline"
		}

		// Mask token so we don't expose full secret in APIs.
		masked := ""
		if len(n.Token) > 4 {
			masked = n.Token[:4] + "****"
		}

		views = append(views, nodeView{
			NodeID:      n.NodeID,
			IP:          n.IP,
			Tags:        n.Tags,
			LastSeen:    n.LastSeen,
			Status:      status,
			TokenMasked: masked,
			TunnelIP:    n.TunnelIP,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(views); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleNodesHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes := s.state.ListNodes()
	now := time.Now().Unix()

	type nodeView struct {
		NodeID      string
		IP          string
		Tags        []string
		LastSeen    int64
		Status      string
		TokenMasked string
		TunnelIP    string
	}

	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		age := now - n.LastSeen

		status := "offline"
		switch {
		case age <= 20:
			status = "healthy"
		case age <= 60:
			status = "stale"
		default:
			status = "offline"
		}

		masked := ""
		if len(n.Token) > 4 {
			masked = n.Token[:4] + "****"
		}

		views = append(views, nodeView{
			NodeID:      n.NodeID,
			IP:          n.IP,
			Tags:        n.Tags,
			LastSeen:    n.LastSeen,
			Status:      status,
			TokenMasked: masked,
			TunnelIP:    n.TunnelIP,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprint(w, "<!DOCTYPE html><html><head><title>Nodes</title>")
	fmt.Fprint(w, `<style>
        body { font-family: sans-serif; padding: 16px; }
        table { border-collapse: collapse; width: 100%; max-width: 900px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #f4f4f4; text-align: left; }
        .healthy { color: green; font-weight: bold; }
        .stale { color: orange; font-weight: bold; }
        .offline { color: red; font-weight: bold; }
    </style></head><body>`)

	fmt.Fprint(w, "<h1>Registered Nodes</h1>")
	fmt.Fprint(w, "<table><tr><th>Node ID</th><th>IP</th><th>Tags</th><th>Last Seen (unix)</th><th>Status</th><th>Token</th></tr>")

	for _, v := range views {
		fmt.Fprintf(w,
			"<tr><td><a href=\"/node/%s\">%s</a></td><td>%s</td><td>%v</td><td>%d</td><td class='%s'>%s</td><td>%s</td></tr>",
			v.NodeID, v.NodeID, v.IP, v.Tags, v.LastSeen, v.Status, v.Status, v.TokenMasked,
		)

	}

	fmt.Fprint(w, "</table></body></html>")
}

func (s *Server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tagsParam := r.URL.Query().Get("tags")
	if tagsParam == "" {
		http.Error(w, "missing tags query param (e.g. ?tags=dev,admin)", http.StatusBadRequest)
		return
	}

	tags := strings.Split(tagsParam, ",")

	// We can reuse the same tag → CIDRs logic as for real nodes.
	allowed := s.state.AllowedCIDRsForTags(tags)

	resp := struct {
		Tags         []string `json:"tags"`
		AllowedCIDRs []string `json:"allowed_cidrs"`
	}{
		Tags:         tags,
		AllowedCIDRs: allowed,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Path is expected as /node/<id>
	prefix := "/node/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	nodeID := strings.TrimPrefix(r.URL.Path, prefix)
	if nodeID == "" {
		http.Error(w, "missing node id", http.StatusBadRequest)
		return
	}

	n := s.state.GetNode(nodeID)
	if n == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	now := time.Now().Unix()
	age := now - n.LastSeen

	status := "offline"
	switch {
	case age <= 20:
		status = "healthy"
	case age <= 60:
		status = "stale"
	default:
		status = "offline"
	}

	allowed := s.state.AllowedCIDRsForTags(n.Tags)

	masked := ""
	if len(n.Token) > 4 {
		masked = n.Token[:4] + "****"
	}

	resp := struct {
		NodeID       string   `json:"node_id"`
		IP           string   `json:"ip"`
		Tags         []string `json:"tags"`
		LastSeenUnix int64    `json:"last_seen_unix"`
		Status       string   `json:"status"`
		AllowedCIDRs []string `json:"allowed_cidrs"`
		TokenMasked  string   `json:"token_masked"`
	}{
		NodeID:       n.NodeID,
		IP:           n.IP,
		Tags:         n.Tags,
		LastSeenUnix: n.LastSeen,
		Status:       status,
		AllowedCIDRs: allowed,
		TokenMasked:  masked,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleReloadPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, err := LoadPolicyConfig(s.policyConfigPath)
	if err != nil {
		log.Printf("reload policy: failed to load config from %s: %v", s.policyConfigPath, err)
		http.Error(w, "failed to load policy config", http.StatusInternalServerError)
		return
	}

	s.state.UpdatePolicyConfig(cfg)
	log.Printf("reload policy: successfully reloaded config from %s", s.policyConfigPath)

	w.WriteHeader(http.StatusNoContent)
}
