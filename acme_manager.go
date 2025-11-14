package main

import (
    "errors"
    "io/fs"
    "log"
    "net/http"
    "time"

    "github.com/go-acme/lego/v4/certificate"
    "github.com/go-acme/lego/v4/certcrypto"
    "github.com/go-acme/lego/v4/challenge/dns01"
    "github.com/go-acme/lego/v4/lego"
)

type CertificateClient interface {
	ObtainCertificate(domains []string) (*certificate.Resource, error)
}

///////////////////////////////////////////////////

type AcmeClient struct {
  client *lego.Client
}

func NewAcmeClient(client *lego.Client) *AcmeClient {
    return &AcmeClient{client: client}
}

func (c *AcmeClient) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	return c.client.Certificate.Obtain(request)
}

func createAcmeClient(server, email, accountPath string, opts []dns01.ChallengeOption) (*AcmeClient, error) {
	var err error
	var account *Account
	if accountPath != "" {
		account, err = ReadAccount(accountPath)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err == nil && (account.Server != server || account.Email != email) {
			log.Printf("existing account details do not match configuration, a new account will be created")
			account = nil
		}
	}
	if account == nil {
		account, err = NewAccount(server, email)
		if err != nil {
			return nil, err
		}
	}

	config := &lego.Config{
		CADirURL:   server,
		User:       account,
		HTTPClient: http.DefaultClient,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.RSA2048,
			Timeout: 30 * time.Second,
		},
	}

	
	legoClient, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	acmeClient := NewAcmeClient(legoClient)

	provider, err := GetDNSProvider()
	if err != nil {
		return nil, err
	}

	acmeClient.client.Challenge.SetDNS01Provider(provider, opts...)

	if account.Registration == nil {
		err = RegisterAccount(acmeClient.client, account)
		if err != nil {
			return nil, err
		}

		if accountPath != "" {
			err = StoreAccount(accountPath, account)
			if err != nil {
				return nil, err
			}
		}
	}

	return acmeClient, nil
}

///////////////////////////////////////////////////

type SelfSignedClient struct {
}

func (c *SelfSignedClient) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	log.Printf("Generating self-signed certificate for %v", domains)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	res, _, err := createSelfSignedCertificate(notAfter)
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

///////////////////////////////////////////////////

