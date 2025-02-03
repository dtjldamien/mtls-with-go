package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	client, err := setupClient()
	if err != nil {
		log.Fatalf("could not setup client: %s\n", err)
	}

	resp, err := client.Get("https://localhost:8443/hello")
	if err != nil {
		log.Fatalf("could not send request: %s\n", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("response: %s\n", body)
}

func setupClient() (*http.Client, error) {
	clientCert, err := tls.LoadX509KeyPair("../certs/client.crt", "../certs/client.key")
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile("../certs/intermediate_ca.crt")
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("could not append CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client, nil
}
