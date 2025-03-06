package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	client, err := setupClient()
	if err != nil {
		log.Fatalf("could not setup client: %s\n", err)
	}

  err = godotenv.Load()
  if err != nil {
    log.Fatal("Error loading .env file")
  }
	endpointUrl := os.Getenv("CRL_ENDPOINT_URL")

	req, err := http.NewRequest("GET", endpointUrl, bytes.NewBuffer(nil))
	if err != nil {
		log.Fatalf("could not form request: %s\n", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("error sending request: %s\n", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("response: %s\n", body)

	crlIntermediateOne, err := os.ReadFile("../certs/crl_intermediate_one.pem")
	if err != nil {
		log.Fatalf("error reading crl intermediate one: %s\n", err)
	}

	combinedCRL := append(body, crlIntermediateOne...)

	err = os.WriteFile("combined_crl.pem", combinedCRL, 0644)
	if err != nil {
			log.Fatalf("error writing combined CRL: %s\n", err)
	}

	log.Printf("Combined CRL saved (%d bytes)\n", len(combinedCRL))

	// Verify CRL format
	if _, err := x509.ParseCRL(combinedCRL); err != nil {
			log.Printf("Warning: combined CRL may not be valid: %s\n", err)
	}
}

func setupClient() (*http.Client, error) {
	clientCert, err := tls.LoadX509KeyPair("../certs/valid_client_one.crt", "../certs/valid_client_one.key")

	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile("../certs/ca_chain.crt")
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("could not append CA certificate")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{clientCert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: false,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout: 30 * time.Second,
	}
	return client, nil
}
