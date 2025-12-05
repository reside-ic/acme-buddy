package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/mock"
)

type wakeup struct {
	time time.Time
	ch   chan<- time.Time
}

type callbacks struct {
	mock.Mock
	time time.Time
	ch   chan wakeup
}

func (c *callbacks) obtainCertificate(domains []string) (*certificate.Resource, error) {
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
func (c *callbacks) after(t time.Duration) <-chan time.Time {
	c.Called(t)

	result := make(chan time.Time, 1)
	c.ch <- wakeup{c.time.Add(t), result}

	return result
}

// Used by test code to synchronize with calls to `after()`. When `after()` is
// called, the callback `f` will be executed. The channel returned by `after()`
// is only written to once `f()` returns - if it returns true. If `f()` returns
// false, the channel returned by `after()` never resolves.
func (c *callbacks) barrier(f func() bool) {
	w := <-c.ch
	c.time = w.time
	if f() {
		w.ch <- c.time
	}
}

func newTestCertManager(renewal time.Duration) (*certManager, *callbacks) {
	callbacks := &callbacks{
		time: time.Now().Round(time.Second),
		ch:   make(chan wakeup),
	}

	m := &certManager{
		domains:            []string{"example.com"},
		obtainCertificate:  callbacks.obtainCertificate,
		installCertificate: callbacks.installCertificate,
		now:                callbacks.now,
		after:              callbacks.after,
		renewal:            renewal,
		noJitter:           true,
	}

	return m, callbacks
}

func createTestCertificate(notAfter time.Time) (*certificate.Resource, *x509.Certificate) {
	certRes, err := createSelfSignedCertificate(notAfter, []string{"localhost"})
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certPem, _ := pem.Decode(certRes.Certificate)
	if certPem == nil {
		log.Fatal("Failed to decode certificate")
	}

	parsedCert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	return certRes, parsedCert
}

// When called with a nil existing certificate, the cert manager should
// immediately try to obtain and install a certificate.
func TestCertificateIsObtainedImmediately(t *testing.T) {
	ctx := t.Context()
	m, callbacks := newTestCertManager(60 * time.Minute)

	cert, _ := createTestCertificate(callbacks.time.Add(180 * time.Minute))
	mock.InOrder(
		callbacks.On("obtainCertificate").Return(cert, nil).Once(),
		callbacks.On("installCertificate", cert).Return(nil).Once(),
		callbacks.On("after", 120*time.Minute).Return().Once(),
	)

	go m.loop(ctx, nil, nil)

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)
		return false
	})
}

func TestSleepsUntilCertificateExpiry(t *testing.T) {
	ctx := t.Context()
	m, callbacks := newTestCertManager(60 * time.Minute)
	callbacks.On("after", 120*time.Minute).Return().Once()

	_, cert := createTestCertificate(callbacks.time.Add(180 * time.Minute))

	go m.loop(ctx, cert, nil)

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)
		callbacks.On("after", mock.Anything).Unset()

		renewedCert, _ := createTestCertificate(callbacks.time.Add(240 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(renewedCert, nil).Once(),
			callbacks.On("installCertificate", renewedCert).Return(nil).Once(),
			callbacks.On("after", 180*time.Minute).Return().Once(),
		)

		return true
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		return false
	})
}

// If obtaining a certificate fails, the certificate manager should retry after
// a short delay. The retry follows an exponential backoff.
func TestIssuanceIsRetriedOnError(t *testing.T) {
	ctx := t.Context()

	m, callbacks := newTestCertManager(60 * time.Minute)
	callbacks.On("obtainCertificate").Return(nil, errors.New("failed"))
	callbacks.On("after", 1*time.Minute)

	go m.loop(ctx, nil, nil)

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		callbacks.On("after", mock.Anything).Unset()
		callbacks.On("after", 2*time.Minute)
		return true
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("after", mock.Anything).Unset()

		// Errors on installCertificate also get retried.
		cert, _ := createTestCertificate(callbacks.time.Add(180 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(cert, nil),
			callbacks.On("installCertificate", cert).Return(errors.New("failure")),
			callbacks.On("after", 4*time.Minute),
		)
		return true
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("installCertificate", mock.Anything).Unset()
		callbacks.On("after", mock.Anything).Unset()

		// Allow the issuance to succeed. Manager will sleep until expiry.
		cert, _ := createTestCertificate(callbacks.time.Add(120 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(cert, nil),
			callbacks.On("installCertificate", cert).Return(nil),
			callbacks.On("after", 60*time.Minute).Return(),
		)

		return true
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		callbacks.On("obtainCertificate", mock.Anything).Unset()
		callbacks.On("installCertificate", mock.Anything).Unset()
		callbacks.On("after", mock.Anything).Unset()

		// Renewal fails again - the exponential backoff is reset.
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(nil, errors.New("failed")),
			callbacks.On("after", 1*time.Minute).Return(),
		)

		return true
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)

		return false
	})
}

func TestCanForceRenewalWithSignal(t *testing.T) {
	ctx := t.Context()

	m, callbacks := newTestCertManager(60 * time.Minute)
	callbacks.On("after", 120*time.Minute).Return().Once()

	_, cert := createTestCertificate(callbacks.time.Add(180 * time.Minute))
	forceRenewal := make(chan os.Signal, 1)
	go m.loop(ctx, cert, forceRenewal)

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)
		cert, _ := createTestCertificate(callbacks.time.Add(120 * time.Minute))
		mock.InOrder(
			callbacks.On("obtainCertificate").Return(cert, nil).Once(),
			callbacks.On("installCertificate", cert).Return(nil).Once(),
			callbacks.On("after", 60*time.Minute).Return(),
		)

		// return false means the sleep never completes - instead the signal is
		// what triggers renewal
		forceRenewal <- syscall.SIGHUP
		return false
	})

	callbacks.barrier(func() bool {
		callbacks.AssertExpectations(t)
		return false
	})
}
