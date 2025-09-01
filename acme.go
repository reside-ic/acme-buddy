package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/backoff"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricCertificateExpiry = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "certificate_expiry_timestamp_seconds",
		Help:      "Current expiry time for the certificate, as a Unix timestamp",
	}, []string{"domain"})

	metricCertificateInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "certificate_info",
		Help:      "Certificate information",
	}, []string{"domain", "fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"})

	metricLatestRenewalTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "latest_renewal_attempt_timestamp_seconds",
		Help:      "Time of the latest renewal attempt, as a Unix timestamp",
	}, []string{"domain"})

	metricLatestSuccessfulRenewalTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "latest_successful_renewal_timestamp_seconds",
		Help:      "Time of the latest sucessful renewal attempt, as a Unix timestamp",
	}, []string{"domain"})

	metricLatestRenewalSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "latest_renewal_attempt_success",
		Help:      "Result of the latest renewal attempt",
	}, []string{"domain"})

	metricNextRenewalTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "acme_buddy",
		Name:      "next_renewal_attempt_timestamp_seconds",
		Help:      "Time of the next renewal attempt",
	}, []string{"domain"})
)

const maxJitter = 8 * time.Minute

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

func ObtainCertificate(client *lego.Client, domains []string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	return client.Certificate.Obtain(request)
}

func createClient(server, email, accountPath string, opts []dns01.ChallengeOption) (*lego.Client, error) {
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

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	provider, err := GetDNSProvider()
	if err != nil {
		return nil, err
	}

	client.Challenge.SetDNS01Provider(provider, opts...)

	if account.Registration == nil {
		err = RegisterAccount(client, account)
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

	return client, nil
}

type certManager struct {
	domains            []string
	renewal            time.Duration
	obtainCertificate  func() (*certificate.Resource, error)
	installCertificate func(cert *certificate.Resource) error
	noJitter           bool

	// These match the time.Now and time.After functions.
	// They get mocked during unit tests.
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

func (m *certManager) needsRenewal(cert *x509.Certificate) bool {
	return cert.NotAfter.Sub(m.now()) < m.renewal
}

func (m *certManager) nextRenewal(cert *x509.Certificate) time.Time {
	t := cert.NotAfter.Add(-m.renewal)
	if !m.noJitter {
		// We add a small amount of random time. This is encouraged by Let's
		// Encrypt to avoid creating load spikes.
		t = t.Add(time.Duration(rand.Int63n(int64(maxJitter))))
	}
	return t
}

// Attempt to issue and install a certificate.
//
// If succesful, it returns the parsed certificate and the time at which to
// perform the next renewal.
func (m *certManager) renew() (*x509.Certificate, time.Time, error) {
	result, err := m.obtainCertificate()
	if err != nil {
		return nil, time.Time{}, err
	}

	certs, err := certcrypto.ParsePEMBundle(result.Certificate)
	if err != nil {
		return nil, time.Time{}, err
	}

	err = m.installCertificate(result)
	if err != nil {
		return nil, time.Time{}, err
	}

	return certs[0], m.nextRenewal(certs[0]), nil
}

func (m *certManager) updateCertificateMetrics(cert *x509.Certificate) {
	fingerprint := sha256.Sum256(cert.Raw)

	metricCertificateExpiry.WithLabelValues(m.domains[0]).Set(float64(cert.NotAfter.Unix()))

	// This metric is designed to match the blackbox_exporter's metric:
	// https://github.com/prometheus/blackbox_exporter/blob/f77c50ed7c0f39b734235931e773cf7b5af1fc8a/prober/tls.go
	// https://github.com/prometheus/blackbox_exporter/blob/f77c50ed7c0f39b734235931e773cf7b5af1fc8a/prober/http.go
	//
	// By comparing eg. the fingerprint reported by acme_buddy and by the
	// blackbox_exporter, once can detect discrepancies between the two which
	// suggests that the HTTP server failed to reload the certificate.
	//
	// Generally, setting a metric does not remove the existing entries with
	// different label values. In this case however we only want to advertise
	// what the current certificate info is, hence the `Reset()` call.
	metricCertificateInfo.Reset()
	metricCertificateInfo.With(prometheus.Labels{
		"domain":             m.domains[0],
		"fingerprint_sha256": hex.EncodeToString(fingerprint[:]),
		"subject":            cert.Subject.String(),
		"issuer":             cert.Issuer.String(),
		"subjectalternative": strings.Join(cert.DNSNames, ","),
		"serialnumber":       fmt.Sprintf("%x", cert.SerialNumber.Bytes()),
	}).Set(1)
}

func (m *certManager) loop(ctx context.Context, initial *x509.Certificate, forceRenewal <-chan os.Signal) error {
	labels := prometheus.Labels{"domain": m.domains[0]}

	var b *backoff.Backoff
	if m.noJitter {
		b = backoff.NewWithoutJitter(24*time.Hour, 1*time.Minute)
	} else {
		b = backoff.New(24*time.Hour, 1*time.Minute)
	}

	var next time.Time
	if initial != nil {
		m.updateCertificateMetrics(initial)
	}
	if initial != nil && !m.needsRenewal(initial) {
		next = m.nextRenewal(initial)
		log.Printf("certificate is still valid until %v, next renewal in %v", initial.NotAfter, next.Sub(m.now()))
	}

	for {
		now := m.now()
		if next.After(now) {
			metricNextRenewalTime.With(labels).Set(float64(m.now().Unix()))

			select {
			case <-ctx.Done():
				return ctx.Err()

			case <-forceRenewal:
				log.Printf("received signal, renewing certificate now")
			case <-m.after(next.Sub(now)):
			}
		}

		var err error
		var cert *x509.Certificate
		cert, next, err = m.renew()
		if err != nil {
			delay := b.Duration()
			log.Printf("certificate issuance failed, retrying in %v: %v", delay, err)

			metricLatestRenewalSuccess.With(labels).Set(0)
			metricLatestRenewalTime.With(labels).Set(float64(m.now().Unix()))
			next = m.now().Add(delay)
		} else {
			b.Reset()
			log.Printf("certificate issued, next renewal in %v", next.Sub(m.now()))

			metricLatestRenewalSuccess.With(labels).Set(1)
			metricLatestSuccessfulRenewalTime.With(labels).Set(float64(m.now().Unix()))
			metricLatestRenewalTime.With(labels).Set(float64(m.now().Unix()))

			m.updateCertificateMetrics(cert)
		}
	}
}

func NewCertManager(client *lego.Client, renewal time.Duration, domains []string, installCertificate func(cert *certificate.Resource) error) *certManager {
	return &certManager{
		domains:             domains,
		renewal:            renewal,
		obtainCertificate:  func() (*certificate.Resource, error) { return ObtainCertificate(client, domains) },
		installCertificate: installCertificate,

		now:   time.Now,
		after: time.After,
	}
}
