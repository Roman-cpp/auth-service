// Command genkey generates an RSA keypair for JWT signing.
//
// The private key (PKCS#8 PEM) stays in the auth-service; the public key
// (PKIX/SPKI PEM) is distributed to consumers as jwt_public.pem.
//
//	go run ./cmd/genkey -out ./secrets         # writes jwt_private.pem + jwt_public.pem
//	go run ./cmd/genkey -bits 4096 -out /etc/sleipnir
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"path/filepath"
)

func main() {
	bits := flag.Int("bits", 2048, "RSA key size in bits")
	out := flag.String("out", ".", "output directory for jwt_private.pem and jwt_public.pem")
	flag.Parse()

	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		log.Fatalf("marshal public key: %v", err)
	}

	if err := os.MkdirAll(*out, 0o700); err != nil {
		log.Fatalf("mkdir %q: %v", *out, err)
	}

	privPath := filepath.Join(*out, "jwt_private.pem")
	pubPath := filepath.Join(*out, "jwt_public.pem")

	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0o600); err != nil {
		log.Fatalf("write private key: %v", err)
	}
	if err := writePEM(pubPath, "PUBLIC KEY", pubDER, 0o644); err != nil {
		log.Fatalf("write public key: %v", err)
	}

	log.Printf("wrote %s (keep secret) and %s (distribute to consumers)", privPath, pubPath)
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
