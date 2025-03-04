package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	server, err := setupServer()
	if err != nil {
		log.Fatalf("could not setup server: %s\n", err)
	}

	http.HandleFunc("/crl.pem", func(w http.ResponseWriter, r *http.Request) {
		crl, err := os.ReadFile("../certs/crl.pem")
		if err != nil {
				http.Error(w, "Could not read CRL", http.StatusInternalServerError)
				return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(crl)
})

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello!")
	})

	log.Println("Starting server on https://localhost:8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("server failed to start: %v", err)
	}
}

func setupServer() (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	// serverCert, err := tls.LoadX509KeyPair("../certs/wrong_cn_server.crt", "../certs/wrong_cn_server.key")
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

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		// ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	return server, nil
}
