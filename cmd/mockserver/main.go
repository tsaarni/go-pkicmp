// Command mockserver is a minimal CMP server for testing.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/internal/mockserver"
	"github.com/tsaarni/go-pkicmp/server"
)

const sharedSecret = "test-shared-secret"

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	h, caKey, caCert, err := mockserver.New()
	if err != nil {
		log.Fatalf("creating handler: %v", err)
	}

	srv := server.New(h,
		server.WithSigner(caKey, caCert),
		server.WithSecretLookup(server.SecretLookupFunc(func(senderKID []byte) ([]byte, error) {
			return []byte(sharedSecret), nil
		})),
		server.WithExtraCerts([]*x509.Certificate{caCert}),
		server.WithSender(pkix.Name{CommonName: "Test CA"}),
		server.WithConfirmWaitTime(30*time.Second),
	)

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	log.Printf("mockserver listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
