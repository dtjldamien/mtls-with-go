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

func getCrl(caCert []byte) ([]byte, error) {
	clientCert, err := tls.LoadX509KeyPair("valid_client_one.crt", "valid_client_one.key")
	if err != nil {
		log.Printf("could not load client certificates")
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Printf("could not append CA certificate")
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

	endpointUrl := os.Getenv("CRL_ENDPOINT")

	req, err := http.NewRequest("GET", endpointUrl, bytes.NewBuffer(nil))
	if err != nil {
		log.Printf("could not form request: %s\n", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("error sending request: %s\n", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body: %s\n", err)
	}

	return body, err
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Print("Error loading .env file")
	}

	caCert, err := os.ReadFile("ca_chain.crt")
	if err != nil {
		log.Fatalf("could not load CA chain bundle")
	}

	crl, err := getCrl(caCert)
	if err != nil {
		log.Print("getting crl")
	}
	log.Printf("crl: %s\n", crl)
}
