# mtls-with-go

This repository is a toy example of how to use mTLS with Go. It contains a simple server and client that communicate over HTTPS using mutual TLS authentication.

## Generating certificates

Update the `client.cnf` and `server.cnf` files with the correct values for your environment. Then run the following command to generate the certificates:

```bash
cd certs
chmod +x generate_certs.sh
./generate-certs.sh
```

## Running the example

Run the server:

```bash
cd server
go run server.go
```

Run Envoy proxy:

```bash
cd envoy
envoy -c envoy-demo.yaml
```

Run the client:

```bash
cd client
go run client.go
```
