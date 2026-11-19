// Loopback-only Go net/http HTTP/2 demo server for the integer-bug lab.
// Stdlib only: TLS + ALPN h2 is enabled automatically by net/http.
// Generates an in-memory self-signed cert so no openssl/cert files are needed.
// Serves /index.html content directly (ServeContent => Range support, no
// FileServer "/index.html" -> "/" canonical redirect).
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(720 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	path := os.Getenv("LAB_INDEX")
	if path == "" {
		path = "/srv/index.html"
	}
	body, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	modtime := time.Now()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", modtime, bytes.NewReader(body))
	})
	srv := &http.Server{
		Addr:      ":443",
		Handler:   h,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned()}, NextProtos: []string{"h2", "http/1.1"}},
	}
	log.Printf("go net/http lab server on :443 serving %d-byte body (h2 via ALPN)", len(body))
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
