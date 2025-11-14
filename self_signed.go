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
func createTestCertificate(notAfter time.Time) (*certificate.Resource, *x509.Certificate) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// This isn't enough entropy and maybe not super compliant but good enough
	// for tests. In go1.24+ we could just set the serial to nil and let
	// x509.CreateCertificate generate a proper one.
	maxSerial := big.NewInt(1 << 32)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		NotAfter: notAfter, 
		SerialNumber: serial,
		NotBefore: time.Now().Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: true,
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
