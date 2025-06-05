package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

const HdbAcmeDefaultUrl = "https://hdb.ic.ac.uk/api/acme/v0/"

type HdbDnsProvider struct {
	BaseUrl  *url.URL
	Username string
	Password string
}

func (c *HdbDnsProvider) update(create bool, fqdn, token string) error {
	fqdn, _ = strings.CutSuffix(fqdn, ".")

	if create {
		log.Printf("creating HDB record for %s", fqdn)
	} else {
		log.Printf("deleting HDB record for %s", fqdn)
	}

	url := c.BaseUrl.JoinPath(fqdn, "auth_token")
	body := map[string]string{"token": fmt.Sprintf("\"%s\"", token)}

	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var method string
	if create {
		method = "PUT"
	} else {
		method = "DELETE"
	}

	req, err := http.NewRequest(method, url.String(), bytes.NewBuffer(encoded))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Request to HDB failed with status code %d", resp.StatusCode)
	}

	if create {
		log.Printf("HDB record for %s created succesfully", fqdn)
	} else {
		log.Printf("HDB record for %s deleted succesfully", fqdn)
	}

	return nil
}

func (p *HdbDnsProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return p.update(true, info.FQDN, info.Value)
}

func (p *HdbDnsProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return p.update(false, info.FQDN, info.Value)
}

func (p *HdbDnsProvider) Timeout() (timeout, interval time.Duration) {
	return 210 * time.Second, dns01.DefaultPollingInterval
}

func NewHdbDNSProvider() (*HdbDnsProvider, error) {
	rawUrl := os.Getenv("HDB_ACME_URL")
	if rawUrl == "" {
		rawUrl = HdbAcmeDefaultUrl
	}
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("Invalid URL: %w", err)
	}

	username := os.Getenv("HDB_ACME_USERNAME")
	password := os.Getenv("HDB_ACME_PASSWORD")

	if username == "" || password == "" {
		return nil, errors.New("HDB credentials missing")
	} else {
		return &HdbDnsProvider{
			BaseUrl:  parsedUrl,
			Username: username,
			Password: password,
		}, nil
	}
}
