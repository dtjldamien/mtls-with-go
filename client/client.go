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
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	client, err := setupClient()
	if err != nil {
		log.Fatalf("could not setup client: %s\n", err)
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
	clientCertPath := os.Getenv("CLIENT_CERT_PATH")
	clientKeyPath := os.Getenv("CLIENT_KEY_PATH")
	caCertPath := os.Getenv("CA_CERT_PATH")

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("could not append CA certificate bundle")
	}

	log.Printf("loaded CA certificate bundle with multiple CAs")

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
