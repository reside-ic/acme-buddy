package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/mock"
)

// Create a test self-signed certificate, using the given notAfter time
func createTestCertificate(notAfter time.Time) (*certificate.Resource, *x509.Certificate) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{NotAfter: notAfter}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "", Bytes: priv}),
	}, cert
}

type callbacks struct {
	mock.Mock
	time time.Time
	ch   chan struct{}
}

func (c *callbacks) obtainCertificate() (*certificate.Resource, error) {
	args := c.Called()
	if args.Get(0) != nil {
		return args.Get(0).(*certificate.Resource), args.Error(1)
	} else {
		return nil, args.Error(1)
	}
}
func (c *callbacks) installCertificate(cert *certificate.Resource) error {
	args := c.Called(cert)
	return args.Error(0)
}
func (c *callbacks) now() time.Time {
	return c.time
}
func (c *callbacks) sleep(t time.Duration) {
	c.time = c.time.Add(t)
	c.Called(t)

	// Write to the channel twice - first time lets the barrier() function
	// known we've reached this point, second write is barrier() letting us
	// proceed.
	<-c.ch
	<-c.ch
}

// Used by test code to synchronize with calls to `sleep()`. Calls to sleep
// block until `barrier` is called.  The `f` callback is invoked while `sleep`
// is still blocked, and when the callback returns `sleep()` is released.
func (c *callbacks) barrier(f func()) {
	c.ch <- struct{}{}
	f()
	c.ch <- struct{}{}
}

func newTestCertManager(renewal time.Duration) (*certManager, *callbacks) {
	callbacks := &callbacks{
		time: time.Now().Round(time.Second),
		ch:   make(chan struct{}),
	}

	m := &certManager{
		obtainCertificate:  callbacks.obtainCertificate,
		installCertificate: callbacks.installCertificate,
		now:                callbacks.now,
		sleep:              callbacks.sleep,
		renewal:            renewal,
		noJitter:           true,
	}

	return m, callbacks
}

// When called with a nil existing certificate, the cert manager should
// immediately try to obtain and install a certificate.
func TestCertificateIsObtainedImmediately(t *testing.T) {
	m, callbacks := newTestCertManager(60 * time.Minute)

	cert, _ := createTestCertificate(callbacks.time.Add(180 * time.Minute))
	mock.InOrder(
		callbacks.On("obtainCertificate").Return(cert, nil).Once(),
		callbacks.On("installCertificate", cert).Return(nil).Once(),
		callbacks.On("sleep", 120*time.Minute).Return().Once(),
	)

	go m.loop(t.Context(), nil)

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)
	})
}

func TestSleepsUntilCertificateExpiry(t *testing.T) {
	m, callbacks := newTestCertManager(60 * time.Minute)
	callbacks.On("sleep", 120*time.Minute).Return().Once()

	_, cert := createTestCertificate(callbacks.time.Add(180 * time.Minute))
	go m.loop(t.Context(), cert)

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)
		callbacks.On("sleep", mock.Anything).Unset()

		renewedCert, _ := createTestCertificate(callbacks.time.Add(240 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(renewedCert, nil).Once(),
			callbacks.On("installCertificate", renewedCert).Return(nil).Once(),
			callbacks.On("sleep", 180*time.Minute).Return().Once(),
		)
	})

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)
	})
}

// If obtaining a certificate fails, the certificate manager should retry after
// a short delay. The retry follows an exponential backoff.
func TestIssuanceIsRetriedOnError(t *testing.T) {
	m, callbacks := newTestCertManager(60 * time.Minute)
	callbacks.On("obtainCertificate").Return(nil, errors.New("failed"))
	callbacks.On("sleep", 1*time.Minute)

	go m.loop(t.Context(), nil)

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)

		callbacks.On("sleep", mock.Anything).Unset()
		callbacks.On("sleep", 2*time.Minute)
	})

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("sleep", mock.Anything).Unset()

		// Errors on installCertificate also get retried.
		cert, _ := createTestCertificate(callbacks.time.Add(180 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(cert, nil),
			callbacks.On("installCertificate", cert).Return(errors.New("failure")),
			callbacks.On("sleep", 4*time.Minute),
		)
	})

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("installCertificate", mock.Anything).Unset()
		callbacks.On("sleep", mock.Anything).Unset()

		// Allow the issuance to succeed. Manager will sleep until expiry.
		cert, _ := createTestCertificate(callbacks.time.Add(120 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(cert, nil),
			callbacks.On("installCertificate", cert).Return(nil),
			callbacks.On("sleep", 60*time.Minute).Return(),
		)
	})

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("installCertificate", mock.Anything).Unset()
		callbacks.On("sleep", mock.Anything).Unset()

		// Renewal fails again - the exponential backoff is reset.
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(nil, errors.New("failed")),
			callbacks.On("sleep", 1*time.Minute).Return(),
		)
	})

	callbacks.barrier(func() {
		callbacks.AssertExpectations(t)
	})
}
