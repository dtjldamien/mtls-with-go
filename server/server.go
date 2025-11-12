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

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	serverCertPath := os.Getenv("SERVER_CERT_PATH")
	serverKeyPath := os.Getenv("SERVER_KEY_PATH")
	caCertPath := os.Getenv("CA_CERT_PATH")

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Fatalf("could not read server cert: %v", err)
	}

	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("could not read ca chain cert: %v", err)
	}

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

		caCertPool.AddCert(cert)
		remainingBytes = rest
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

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "No client certificate provided", http.StatusUnauthorized)
			return
		}

		// read from forwarded header if exists
		xfccHeader := r.Header.Get("x-forwarded-client-cert")
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
		w.WriteHeader(http.StatusOK)
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
