package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

// Create a self-signed certificate, using the given notAfter time
func createSelfSignedCertificate(notAfter time.Time, domains []string) (*certificate.Resource, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		NotAfter:              notAfter,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              domains,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}),
	}, nil
}

type SelfSignedClient struct {
}

func (c *SelfSignedClient) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	log.Printf("Generating self-signed certificate for %v", domains)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	res, err := createSelfSignedCertificate(notAfter, domains)
	if err != nil {
		return nil, err
	}
	return &certificate.Resource{
		Domain:      domains[0],
		Certificate: res.Certificate,
		PrivateKey:  res.PrivateKey,
	}, nil
}

func createSelfSignedClient() *SelfSignedClient {
	return &SelfSignedClient{}
}
