package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/docker/docker/client"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var metricsFlag = flag.String("metrics", ":2112", "The host and port on which to expose metrics.")
var serverFlag = flag.String("server", "", "The URL to the ACME server's directory. If unset, Let's Encrypt is used by default.")
var stagingFlag = flag.Bool("staging", false, "Use the staging Let's Encrypt environment.")
var domainFlag = flag.String("domain", "", "The domain name to use in the certificate.")
var emailFlag = flag.String("email", "", "The email address used for registration.")

var forceFlag = flag.Bool("force", false, "Renew the certificate even if the existing one is still valid.")
var oneshotFlag = flag.Bool("oneshot", false, "Renew the certificate (if needed) and exit immediately.")
var daysFlag = flag.Int("days", 30, "The number of days left on a certificate before it is renewed.")
var providerFlag = flag.String("dns-provider", "", "The DNS provider to use to provision challenges.")
var dnsDisableCompletePropagationFlag = flag.Bool("dns-disable-cp", false, "Do not wait for propagation of the DNS records before requesting a certificate.")

var tlsSkipVerifyFlag = flag.Bool("tls-skip-verify", false, "Skip TLS verification. This is insecure and should only be used during tests.")

var certificatePathFlag = flag.String("certificate-path", "", "Path where the certificate chain is stored.")
var keyPathFlag = flag.String("key-path", "", "Path where the private key is stored.")
var accountPathFlag = flag.String("account-path", "", "Path where the account information is stored.")

var reloadContainerFlag = flag.String("reload-container", "", "Name of container to reload after a new certificate is issued.")
var reloadSignalFlag = flag.String("reload-signal", "SIGHUP", "Signal used to reload the container.")

func reloadContainer(name, signal string) error {
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return client.ContainerKill(context.Background(), name, signal)
}

func installCertificate(cert *certificate.Resource) error {
	if *certificatePathFlag != "" {
		err := os.WriteFile(*certificatePathFlag, cert.Certificate, 0644)
		if err != nil {
			return err
		}
	}

	if *keyPathFlag != "" {
		err := os.WriteFile(*keyPathFlag, cert.PrivateKey, 0644)
		if err != nil {
			return err
		}
	}

	if *reloadContainerFlag != "" {
		log.Printf("reloading container %s", *reloadContainerFlag)
		err := reloadContainer(*reloadContainerFlag, *reloadSignalFlag)
		if err != nil {
			log.Printf("could not reload container: %v", err)
		}
	}

	return nil
}

func main() {
	flag.Parse()

	if *tlsSkipVerifyFlag {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	server := *serverFlag
	if server == "" {
		if *stagingFlag {
			server = lego.LEDirectoryStaging
		} else {
			server = lego.LEDirectoryProduction
		}
	} else if *stagingFlag {
		log.Fatal("Cannot specify both --staging and --server")
	}

	if *domainFlag == "" || *emailFlag == "" {
		log.Fatal("--domain and --email must be set")
	}

	// Checking propagation of DNS records won't work during integration tests.
	// The flag allows us to skip that.
	dnsOpts := []dns01.ChallengeOption{
		dns01.CondOption(
			*dnsDisableCompletePropagationFlag,
			dns01.DisableCompletePropagationRequirement()),
	}

	client, err := createClient(server, *emailFlag, *accountPathFlag, dnsOpts)
	if err != nil {
		log.Fatalf("could not create client: %v", err)
	}

	var cert *x509.Certificate
	if *certificatePathFlag != "" && !*forceFlag {
		certs, err := LoadCertificate(*certificatePathFlag)
		if err != nil {
			log.Printf("could not read certificate, will request a new one: %v", err)
		} else if !slices.Equal(certs[0].DNSNames, []string{*domainFlag}) {
			log.Printf("DNS names in existing certificate do not match, will request a new certificate")
		} else {
			cert = certs[0]
		}
	}

	m := NewCertManager(client, time.Duration(*daysFlag)*24*time.Hour, *domainFlag, installCertificate)
	if *oneshotFlag {
		if cert == nil || m.needsRenewal(cert) {
			cert, _, err := m.renew()
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("issued certificate is valid until %v", cert.NotAfter)
		} else {
			log.Printf("certificate is still valid until %v", cert.NotAfter)
		}
	} else {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(*metricsFlag, nil)
		m.loop(context.Background(), cert)
	}
}
