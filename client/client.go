package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"

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
	endpointUrl := os.Getenv("ENDPOINT_URL")
  apiKey := os.Getenv("API_KEY")

	req, err := http.NewRequest("GET", endpointUrl, bytes.NewBuffer(nil))
	if err != nil {
		log.Fatalf("could not form request: %s\n", err)
	}

	req.Header.Set("api-token", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("error sending request: %s\n", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("response: %s\n", body)
}

func setupClient() (*http.Client, error) {
	clientCert, err := tls.LoadX509KeyPair("../certs/valid_client_one.crt", "../certs/valid_client_one.key")
	// clientCert, err := tls.LoadX509KeyPair("../certs/valid_client_two.crt", "../certs/valid_client_two.key")
	// clientCert, err := tls.LoadX509KeyPair("../certs/revoked_client_one.crt", "../certs/revoked_client_one.key")
	// clientCert, err := tls.LoadX509KeyPair("../certs/revoked_client_two.crt", "../certs/revoked_client_two.key")
	// clientCert, err := tls.LoadX509KeyPair("../certs/rogue_client.crt", "../certs/rogue_client.key")

	// if err != nil {
	// 	return nil, err
	// }

	caCert, err := os.ReadFile("../certs/ca_chain.crt")
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
