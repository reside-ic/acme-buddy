package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	imagepkg "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/volume"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	networkpkg "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

var imageFlag = flag.String("image", "", "Image name to test")

func createTestCertificate(template x509.Certificate) (*certificate.Resource, *x509.Certificate, error) {
	// This isn't enough entropy and maybe not super compliant but good enough
	// for tests. In go1.24+ we could just leave the serial set to nil and let
	// x509.CreateCertificate generate a proper one.
	if template.SerialNumber == nil {
		maxSerial := big.NewInt(1 << 32)
		serial, err := rand.Int(rand.Reader, maxSerial)
		if err != nil {
			return nil, nil, err
		}
		template.SerialNumber = serial
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}),
	}, cert, nil
}

func getPeerCertificates(endpoint string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

type TestSuite struct {
	suite.Suite
	provider        *tc.DockerProvider
	image           string
	network         *tc.DockerNetwork
	pebbleContainer tc.Container

	// Pebble's API is only available over TLS. The CA that was used to sign that
	// cert needs to be trusted by acme-buddy or else it won't be able to
	// connect.
	//
	// This is the CA that signs Pebble's API certificate. It is not the root
	// certificate that Pebble uses to sign certificates it issues.
	//
	// The CA's root cert is available inside the pebble image.  After starting
	// the container, we get the certificate out and store it here. When running
	// the acme-buddy image, we'll inject the certificate into the container as a
	// trusted root.
	//
	// See https://github.com/letsencrypt/pebble/pull/65
	pebbleMiniCA []byte
}

// Returns a context that is cancelled at the end of the test.
//
// In go1.24+ this can be replaced by t.Context()
func (suite *TestSuite) Context() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	suite.T().Cleanup(cancel)
	return ctx
}

func (suite *TestSuite) SetupSuite() {
	t := suite.T()
	ctx := suite.Context()

	provider, err := tc.NewDockerProvider()
	require.NoError(t, err)
	t.Cleanup(func() { provider.Close() })
	suite.provider = provider

	if *imageFlag != "" {
		suite.image = *imageFlag
	} else {
		image, err := provider.BuildImage(ctx, &tc.ContainerRequest{
			FromDockerfile: tc.FromDockerfile{
				Context:        "../",
				BuildLogWriter: os.Stdout,
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			provider.Client().ImageRemove(context.Background(), image, imagepkg.RemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
		})
		suite.image = image
	}

	network, err := networkpkg.New(ctx)
	require.NoError(t, err)
	tc.CleanupNetwork(t, network)
	suite.network = network

	container, err := startChallTestSrv(ctx, network)
	require.NoError(t, err)
	tc.CleanupContainer(t, container)

	container, err = startPebble(ctx, network)
	require.NoError(t, err)
	tc.CleanupContainer(t, container)
	suite.pebbleContainer = container

	stream, err := suite.pebbleContainer.CopyFileFromContainer(ctx, "test/certs/pebble.minica.pem")
	require.NoError(t, err)
	defer stream.Close()

	suite.pebbleMiniCA, err = io.ReadAll(stream)
	require.NoError(t, err)
}

func (suite *TestSuite) runAcmeBuddy(domain string, opts ...tc.ContainerCustomizer) (*tc.DockerContainer, error) {
	ctx := suite.Context()

	opts = append([]tc.ContainerCustomizer{
		tc.WithLogConsumers(&tc.StdoutLogConsumer{}),
		network.WithNetwork([]string{}, suite.network),
		tc.WithCmd(
			"--email=admin@example.com",
			"--server=https://pebble:14000/dir",
			"--dns-provider=hdb",
			"--dns-disable-cp",
			"--domain", domain,
			"--certificate-path=/tls/certificate.pem",
			"--key-path=/tls/key.pem"),
		tc.WithEnv(map[string]string{
			"HDB_ACME_URL":      "http://challtestsrv:8080",
			"HDB_ACME_USERNAME": "foo",
			"HDB_ACME_PASSWORD": "bar",
			"SSL_CERT_FILE":     "/minica.pem",
		}),
		tc.WithFiles(tc.ContainerFile{
			Reader:            bytes.NewReader(suite.pebbleMiniCA),
			ContainerFilePath: "/minica.pem",
		}),
	}, append(opts, WithDefaultVolumeMount("/tls"))...)

	return tc.Run(ctx, suite.image, opts...)
}

func readCertificateFromContainer(ctx context.Context, container tc.Container) (tls.Certificate, error) {
	certBytes, err := copyFileFromContainer(ctx, container, "/tls/certificate.pem")
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, err := copyFileFromContainer(ctx, container, "/tls/key.pem")
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certBytes, keyBytes)
}

func (suite *TestSuite) obtainCertificate(domain string, opts ...tc.ContainerCustomizer) (tls.Certificate, error) {
	ctx := suite.Context()

	opts = append([]tc.ContainerCustomizer{
		tc.WithWaitStrategy(WaitForSuccess()),
		tc.WithCmdArgs("--oneshot"),
	}, opts...)

	container, err := suite.runAcmeBuddy(domain, opts...)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer container.Terminate(context.Background())

	return readCertificateFromContainer(ctx, container)
}

func (suite *TestSuite) GetRootCA(ctx context.Context) (*x509.Certificate, error) {
	endpoint, err := suite.pebbleContainer.PortEndpoint(ctx, "15000/tcp", "https")
	if err != nil {
		return nil, err
	}
	url, err := url.JoinPath(endpoint, "roots/0")
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	certs, err := certcrypto.ParsePEMBundle(body)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

func (suite *TestSuite) TestCanObtainCertificate() {
	ctx := suite.Context()
	cert, err := suite.obtainCertificate("www.example.com")
	suite.Require().NoError(err)
	suite.Equal(cert.Leaf.DNSNames, []string{"www.example.com"})

	root, err := suite.GetRootCA(ctx)
	suite.Require().NoError(err)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		suite.Require().NoError(err)
		intermediates.AddCert(c)
	}

	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:       "www.example.com",
		Roots:         roots,
		Intermediates: intermediates,
	})
	suite.Require().NoError(err)
}

func (suite *TestSuite) TestCertificateRenewal() {
	const Day time.Duration = 24 * time.Hour

	tests := map[string]struct {
		originalExpiry  time.Time
		originalDomains []string
		shouldRenew     bool
	}{
		"Certificate is still valid": {
			originalExpiry:  time.Now().Add(60 * Day),
			originalDomains: []string{"www.example.com"},
			shouldRenew:     false,
		},
		"Certificate is valid but has a different domain name": {
			originalExpiry:  time.Now().Add(60 * Day),
			originalDomains: []string{"foo.com"},
			shouldRenew:     true,
		},
		"Certificate is valid but has extra domain name": {
			originalExpiry:  time.Now().Add(60 * Day),
			originalDomains: []string{"www.example.com", "foo.com"},
			shouldRenew:     true,
		},
		"Certificate is valid but expires soon": {
			originalExpiry:  time.Now().Add(15 * Day),
			originalDomains: []string{"www.example.com"},
			shouldRenew:     true,
		},
		"Certificate has expired": {
			originalExpiry:  time.Now().Add(-15 * Day),
			originalDomains: []string{"www.example.com"},
			shouldRenew:     true,
		},
	}

	for name, tt := range tests {
		suite.T().Run(name, func(t *testing.T) {
			resource, initialCert, err := createTestCertificate(x509.Certificate{
				DNSNames: tt.originalDomains,
				NotAfter: tt.originalExpiry,
			})
			require.NoError(t, err)

			updatedCert, err := suite.obtainCertificate("www.example.com", WithInitialCertificate(resource))
			require.NoError(t, err)

			if tt.shouldRenew {
				assert.NotEqual(t, initialCert.SerialNumber, updatedCert.Leaf.SerialNumber)
			} else {
				assert.Equal(t, initialCert, updatedCert.Leaf)
			}
		})
	}
}

func (suite *TestSuite) TestCanReloadContainer() {
	t := suite.T()
	ctx := suite.Context()

	client, err := tc.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)

	volume, err := client.VolumeCreate(ctx, volume.CreateOptions{Labels: tc.GenericLabels()})
	require.NoError(t, err)

	mounts := tc.WithMounts(tc.ContainerMount{
		Source: tc.DockerVolumeMountSource{Name: volume.Name},
		Target: "/tls",
	})

	resource, _, err := createTestCertificate(x509.Certificate{
		DNSNames: []string{"www.example.com"},
	})
	require.NoError(t, err)

	cfg := `
error_log stderr info;
http {
  server {
    listen              443 ssl;
    server_name         www.example.com;
    ssl_certificate     /tls/certificate.pem;
    ssl_certificate_key /tls/key.pem;
  }
}
events { }
`
	nginx, err := startNginx(ctx, mounts,
		tc.WithExposedPorts("443/tcp"),
		tc.WithWaitStrategy(wait.ForListeningPort("443/tcp")),
		WithNginxConfig(cfg),
		WithInitialCertificate(resource),
	)
	require.NoError(t, err)

	endpoint, err := nginx.PortEndpoint(ctx, "443/tcp", "")
	require.NoError(t, err)

	initialCerts, err := getPeerCertificates(endpoint)
	require.NoError(t, err)

	_, err = suite.obtainCertificate("www.example.com", mounts,
		tc.WithCmdArgs("--reload-container", nginx.GetContainerID(), "--force"),
		WithBindMountedDockerSocket(ctx),
	)
	require.NoError(t, err)

	// We have to wait until the old worker process has exited as a sign that
	// nginx has finished reloading.
	err = wait.ForLog(`worker process \d+ exited with code \d+`).AsRegexp().WaitUntilReady(ctx, nginx)
	require.NoError(t, err)

	updatedCerts, err := getPeerCertificates(endpoint)
	require.NoError(t, err)

	assert.NotEqual(t, updatedCerts[0].SerialNumber, initialCerts[0].SerialNumber)
}

func (suite *TestSuite) TestCanForceRenewalWithSignal() {
	t := suite.T()
	ctx := suite.Context()

	container, err := suite.runAcmeBuddy("www.example.com")
	require.NoError(t, err)
	tc.CleanupContainer(t, container)

	err = wait.ForLog("certificate issued, next renewal in").WaitUntilReady(ctx, container)
	require.NoError(t, err)

	initialCert, err := readCertificateFromContainer(ctx, container)
	require.NoError(t, err)

	err = suite.provider.Client().ContainerKill(ctx, container.ID, "SIGHUP")
	require.NoError(t, err)

	err = wait.ForLog("certificate issued, next renewal in").WithOccurrence(2).WaitUntilReady(ctx, container)
	require.NoError(t, err)

	renewedCert, err := readCertificateFromContainer(ctx, container)
	require.NoError(t, err)

	assert.NotEqual(t, renewedCert.Leaf.SerialNumber, initialCert.Leaf.SerialNumber)
}

func TestRunTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
