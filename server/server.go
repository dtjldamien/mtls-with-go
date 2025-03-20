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
		clientCert := r.TLS.PeerCertificates[0]
		xfccHeader := r.Header.Get("x-forwarded-client-cert")

		if xfccHeader != "" {
			cert, err := parseForwardedCert(xfccHeader)
			if cert != nil {
				clientCert = cert
			} else {
				log.Printf("errors parsing xfcc cert: %v", err)
			}
		}

		log.Printf("Client connected with certificate: %s", clientCert.SerialNumber)

		// check if client cert has been revoked
		for _, crl := range crls {
			for _, entry := range crl.RevokedCertificateEntries {
				if clientCert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					log.Printf("Rejected revoked certificate: %s", clientCert.SerialNumber)
					http.Error(w, "Certificate has been revoked", http.StatusUnauthorized)
					return
				}
			}
		}

		// check if client cert has allowed subject CN and SAN
		allowedCN := os.Getenv("ALLOWED_CN")
		if clientCert.Subject.CommonName != allowedCN {
			log.Printf("invalid CN: expected %s, got %s",
				allowedCN, clientCert.Subject.CommonName)
			return
		}

		// Check SANs
		found := false
		allowedSAN := os.Getenv("ALLOWED_SAN")
		for _, san := range clientCert.DNSNames {
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

		fmt.Fprintf(w, "hello!")
	})

	log.Println("Starting server on https://localhost:8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("server failed to start: %v", err)
	}
}

func parseForwardedCert(xfccHeader string) (*x509.Certificate, error) {
	log.Println("xfcc header: %s", xfccHeader)
	firstXfcc := strings.Split(xfccHeader, ",")[0]
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
