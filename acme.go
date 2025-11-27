package main

import (
	"crypto/x509"
	"errors"
	"io/fs"	
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)


const maxJitter = 8 * time.Minute

type CertificateClient interface {
	ObtainCertificate(domains []string) (*certificate.Resource, error)
}

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

func GetDNSProvider() (challenge.Provider, error) {
	switch *providerFlag {
	case "hdb":
		return NewHdbDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	default:
		return nil, errors.New("Unknown or missing DNS provider")
	}
}

func LoadCertificate(path string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return certcrypto.ParsePEMBundle(bytes)
}

func RegisterAccount(client *lego.Client, account *Account) error {
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	account.Registration = reg
	return nil
}



