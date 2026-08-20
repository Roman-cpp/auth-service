package handler

import (
	"log"
	"net/http"

	"github.com/krypton/auth-service/internal/keys"
)

// JWKSHandler publishes the auth-service public keys so consumers can verify
// tokens offline. It exposes both a JWKS document (preferred, with kid) and a
// raw PKIX PEM (jwt_public.pem) for consumers that load a single static key.
type JWKSHandler struct {
	keys *keys.KeySet
}

func NewJWKSHandler(ks *keys.KeySet) *JWKSHandler {
	return &JWKSHandler{keys: ks}
}

// JWKS serves GET /.well-known/jwks.json.
func (h *JWKSHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	body, err := h.keys.JWKS()
	if err != nil {
		log.Printf("JWKS: %v", err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

// PublicPEM serves GET /.well-known/jwt_public.pem.
func (h *JWKSHandler) PublicPEM(w http.ResponseWriter, r *http.Request) {
	pem, err := h.keys.PublicPEM()
	if err != nil {
		log.Printf("PublicPEM: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(pem)
}
