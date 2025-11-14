package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)


// Create a test self-signed certificate, using the given notAfter time
func createSelfSignedCertificate(notAfter time.Time) (*certificate.Resource, *x509.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		NotAfter: notAfter,
		NotBefore: time.Now().Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}
	
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}),
	}, cert
}
