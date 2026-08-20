// Package keys manages the RSA key material used to sign and verify JWTs.
//
// The Auth-service is the single source of identity: it holds the RSA private
// key and signs access tokens with RS256. Consumers (trading-backend,
// keys-service) verify tokens offline using the public key, which is published
// as a PKIX/SPKI PEM (jwt_public.pem) and via the JWKS endpoint.
//
// To support no-downtime rotation, a KeySet keeps one active signing key plus
// any number of additional public keys that remain valid for verification
// until every consumer has cycled to the new key.
package keys

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// KeySet holds the active signing key and all public keys valid for
// verification, indexed by key id (kid).
type KeySet struct {
	private   *rsa.PrivateKey
	activeKID string
	verifiers map[string]*rsa.PublicKey
}

// Load reads the RSA private key from privatePath (PKCS#1 or PKCS#8 PEM) and
// derives the active public key. Any extra public-key PEM paths are loaded as
// verify-only keys so tokens signed by a previous key keep validating during
// rotation.
func Load(privatePath string, additionalPublicPaths []string) (*KeySet, error) {
	if privatePath == "" {
		return nil, errors.New("keys: private key path is empty")
	}

	priv, err := loadPrivateKey(privatePath)
	if err != nil {
		return nil, err
	}

	activeKID, err := computeKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	ks := &KeySet{
		private:   priv,
		activeKID: activeKID,
		verifiers: map[string]*rsa.PublicKey{activeKID: &priv.PublicKey},
	}

	for _, p := range additionalPublicPaths {
		pub, err := loadPublicKey(p)
		if err != nil {
			return nil, err
		}
		kid, err := computeKID(pub)
		if err != nil {
			return nil, err
		}
		// The active key wins if an additional path resolves to it.
		if _, ok := ks.verifiers[kid]; !ok {
			ks.verifiers[kid] = pub
		}
	}

	return ks, nil
}

// Private returns the active RSA signing key.
func (ks *KeySet) Private() *rsa.PrivateKey { return ks.private }

// ActiveKID returns the key id placed in the `kid` header of issued tokens.
func (ks *KeySet) ActiveKID() string { return ks.activeKID }

// PublicKeyByKID returns the verification key for the given kid.
func (ks *KeySet) PublicKeyByKID(kid string) (*rsa.PublicKey, bool) {
	pub, ok := ks.verifiers[kid]
	return pub, ok
}

// PublicPEM returns the active public key encoded as a PKIX/SPKI PEM block —
// the artifact distributed to consumers as jwt_public.pem.
func (ks *KeySet) PublicPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&ks.private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// JWKS marshals every verification key into a JWKS document
// (the body served at /.well-known/jwks.json).
func (ks *KeySet) JWKS() ([]byte, error) {
	keys := make([]jwk, 0, len(ks.verifiers))
	for kid, pub := range ks.verifiers {
		keys = append(keys, jwk{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E)),
		})
	}
	return json.Marshal(jwkSet{Keys: keys})
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// computeKID derives a stable key id from the SHA-256 of the DER-encoded
// public key, base64url-encoded. The same public key always yields the same
// kid, so consumers and issuer agree without extra configuration.
func computeKID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("keys: marshal public key for kid: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keys: read private key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keys: no PEM block in %q", path)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key %q (tried PKCS#1 and PKCS#8): %w", path, err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: %q is not an RSA private key", path)
	}
	return rsaKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keys: read public key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keys: no PEM block in %q", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse public key %q: %w", path, err)
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keys: %q is not an RSA public key", path)
	}
	return rsaKey, nil
}

func bigEndianExponent(e int) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	// Trim leading zero bytes (typical exponent 65537 -> 0x010001).
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}
