package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"	
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

// Create a self-signed certificate, using the given notAfter time
func createSelfSignedCertificate(notAfter time.Time) (*certificate.Resource, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, err
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}),
	}, nil
}

func createTestCertificate(notAfter time.Time) (*certificate.Resource, *x509.Certificate, error) {
  certRes, err := createSelfSignedCertificate(notAfter)
	if err != nil {
	  return nil, nil, err
  }
	
	cert_pem, _ := pem.Decode(certRes.Certificate)
	if cert_pem == nil {
	  return nil, nil, fmt.Errorf("Failed to decode certificate")
  }
	
	parsed_cert, err := x509.ParseCertificate(cert_pem.Bytes)
	if err != nil {
	  return nil, nil, err
	}
	return certRes, parsed_cert, nil
}

type SelfSignedClient struct {
}

func (c *SelfSignedClient) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	log.Printf("Generating self-signed certificate for %v", domains)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	res, err := createSelfSignedCertificate(notAfter)
	if err != nil {
		return nil, err
	}
	return &certificate.Resource{
		Domain:       domains[0],
		Certificate:  res.Certificate,
		PrivateKey:   res.PrivateKey,
	}, nil
}

func createSelfSignedClient() *SelfSignedClient {
	return &SelfSignedClient{}
}
