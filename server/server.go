package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	// serverCert, err := tls.LoadX509KeyPair("../certs/wrong_cn_server.crt", "../certs/wrong_cn_server.key")
	if err != nil {
		log.Fatalf("could not read server cert: %v", err)
	}
	log.Printf("server cert: %s", serverCert.Leaf.Subject.String())
	log.Printf("server cert dns names: %s", serverCert.Leaf.DNSNames)
	log.Printf("server cert email addresses: %s", serverCert.Leaf.EmailAddresses)
	log.Printf("server cert URIs: %s", serverCert.Leaf.URIs)
	log.Printf("server cert IP addresses: %s", serverCert.Leaf.IPAddresses)

	caBytes, err := os.ReadFile("../certs/ca_chain.crt")
	if err != nil {
		log.Fatalf("could not read ca chain cert: %v", err)
	}

	var caCerts []*x509.Certificate
	caCertPool := x509.NewCertPool()
	remainingBytes := caBytes

	for {
		block, rest := pem.Decode(remainingBytes)
		if block == nil {
			break // No more PEM blocks to process
		}

		if block.Type != "CERTIFICATE" {
			log.Fatalf("expected CERTIFICATE block, got %s", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse certificate: %v", err)
		}

		caCerts = append(caCerts, cert)
		caCertPool.AddCert(cert)

		remainingBytes = rest
	}

	crlBytes, err := os.ReadFile("../certs/crl.pem")
	if err != nil {
		log.Fatalf("failed to read CRL: %v", err)
	}

	var crls []*x509.RevocationList
	remainingCRLBytes := crlBytes

	for {
		block, rest := pem.Decode(remainingCRLBytes)
		if block == nil {
			break // No more PEM blocks to process
		}

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse CRL: %v", err)
		}

		// Verify CRL signature against CA certificates
		var verified bool
		for _, caCert := range caCerts {
			if err := crl.CheckSignatureFrom(caCert); err == nil {
				verified = true
				break
			}
		}
		if !verified {
			log.Fatalf("CRL signature verification failed")
		}

		// Check CRL validity period
		if crl.ThisUpdate.After(time.Now()) || crl.NextUpdate.Before(time.Now()) {
			log.Fatalf("CRL is not valid at this time")
		}

		crls = append(crls, crl)
		remainingCRLBytes = rest
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/crl.pem", func(w http.ResponseWriter, r *http.Request) {
		intermediateCrl, err := os.ReadFile("../certs/crl_intermediate_two.pem")

		if err != nil {
			http.Error(w, "Could not read CRL", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text-plain")
		w.Write(intermediateCrl)
	})

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "No client certificate provided", http.StatusUnauthorized)
			return
		}

		// read from forwarded header if exists
		xfccHeader := r.Header.Get("x-forwarded-client-cert")
		// xfccHeader := "Hash=8a503e0745a67ccdc1f5fb0080386488789a0dae08bde585c213ef8ecb17650f;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIID2TCCAsGgAwIBAgIBCDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJVUzET%0AMBEGA1UECAwKQ2FsaWZvcm5pYTEaMBgGA1UECgwRSW50ZXJtZWRpYXRlIENvcnAx%0AHDAaBgNVBAMME2ludGVybWVkaWF0ZV9jYV9vbmUwHhcNMjUwNDAxMTMzNzQxWhcN%0AMjYwNDAxMTMzNzQxWjBTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5p%0AYTEUMBIGA1UECgwLQ2xpZW50IENvcnAxGTAXBgNVBAMMEHZhbGlkX2NsaWVudF9v%0AbmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdQF%2F2cxhQtAT2zPyr%0AG%2FdrreWbQtRi2OklZC8BzkjRmw3IlyWZ9Y0JHK4drDfQnIKjzO4TljFPCkVC6zw%2F%0A%2FJ3f3hOwky%2BhIfb0XNbVffaVx5imPEkFvVxweuUi4aFI502rq5HNNoC4L0rNoll2%0A8Pu905LdVhzIECQ3ojiMjUNFzArsBM%2BYZWP7uxSHgJekJ32559db1r%2FHkP7Haho4%0Ay1AClQtwuLk2QRPWFixHE5JEc2eEnOz2eMec2UNE6yDlJi1G%2BbBEvf4MpHKO5NSy%0AHfJ3bUVQr8qO1VBsbZT%2BY9zdHwxrgr2Jgb%2FIropMyjyukrnCfQBgMhmXD6eIUCXz%0ApYStAgMBAAGjga4wgaswCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwHQYDVR0lBBYw%0AFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSpRQKF0cn4zomgl%2FonzNJy%0Axcns0TAfBgNVHSMEGDAWgBS0e8dqaXaXbmC6%2BHKwpU4A1TpZGTAyBgNVHREEKzAp%0Agglsb2NhbGhvc3SCFmFwaS5pZGVhLWxpZmVzdHlsZS5uZXSHBH8AAAEwDQYJKoZI%0AhvcNAQELBQADggEBALKoWdY2UV64pX2M6OYtkzGlC74TwrQkLS%2B3FdYQPwvH77dU%0AN0CyMysKVownS1vvJD4aef5KH8OsHK9vvQVhgy%2FtO4xtul26jdpG48B6dkyq8WH6%0AnD3JNtbRaNpj4HYE3rYpRUEvax15krc8oz8Txd8G8oKiXP4EHCpirTBu5xSO%2FvtK%0AcIwq1N1x20jiUxgWtbzmNsqPdgPk%2BmqH3kD5lWTEdawUW%2F1vqZn6vfK%2FsmkB1xO8%0ADgXQrWRBKoglTreNlpofrwzHjDA7Ub%2FoNxbnmBgPKE91pP0m%2FcSclGzs3Nu2RMiF%0APoHJbn8kI8Q0atqcQ9uaRjvwV3lObLqEAAot%2FjE%3D%0A-----END%20CERTIFICATE-----%0A\""
		log.Printf("xfcc header: %s", xfccHeader)

		if xfccHeader == "" {
			log.Printf("no xfcc header")
			return
		}

		cert, err := parseForwardedCert(xfccHeader)
		if err != nil {
			log.Printf("errors parsing xfcc cert: %v", err)
		}

		log.Printf("Client connected with certificate: %s", cert.SerialNumber)

		// check if client cert has been revoked
		for _, crl := range crls {
			for _, entry := range crl.RevokedCertificateEntries {
				if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					log.Printf("Rejected revoked certificate: %s", cert.SerialNumber)
					http.Error(w, "Certificate has been revoked", http.StatusUnauthorized)
					return
				}
			}
		}

		// check if client cert has allowed subject CN and SAN
		allowedCN := os.Getenv("ALLOWED_CN")
		if cert.Subject.CommonName != allowedCN {
			log.Printf("invalid CN: expected %s, got %s",
				allowedCN, cert.Subject.CommonName)
			return
		}

		// Check SANs
		found := false
		allowedSAN := os.Getenv("ALLOWED_SAN")
		for _, san := range cert.DNSNames {
			log.Printf("client cert dns name: %s", san)
			if san == allowedSAN {
				found = true
				break
			}
		}

		if !found {
			log.Printf("required SAN %s not found", allowedSAN)
			return
		}

		fmt.Print(xfccHeader)
	})

	log.Println("Starting server on https://localhost:8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("server failed to start: %v", err)
	}
}

func parseForwardedCert(xfccHeader string) (*x509.Certificate, error) {
	xfccParts := strings.Split(xfccHeader, ",")
	firstXfcc := xfccParts[len(xfccParts)-1]
	parts := strings.Split(firstXfcc, ";")

	var certPEM string

	for _, part := range parts {
		if strings.HasPrefix(part, "Cert=") {
			// Remove Cert= prefix and decode URL encoding
			certPEM = strings.TrimPrefix(part, "Cert=")
			certPEM = strings.Trim(certPEM, "\"")
			decoded, err := url.QueryUnescape(certPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to decode URL-encoded certificate: %v", err)
			}
			certPEM = decoded
			break // Found the certificate part, exit loop
		}
	}

	if certPEM == "" {
		return nil, fmt.Errorf("no certificate found in XFCC header")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}
