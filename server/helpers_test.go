package server_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tsaarni/certyaml"
	"github.com/tsaarni/go-pkicmp/pkicmp"
	"github.com/tsaarni/go-pkicmp/server"
)

// mockHandler implements server.Handler for testing.
type mockHandler struct {
	handleCertRequest func(ctx context.Context, req *server.CertRequest) (*server.CertResponse, error)
	handleCertConfirm func(ctx context.Context, confirm *server.CertConfirmation) error
	handlePollRequest func(ctx context.Context, poll *server.PollRequest) (*server.CertResponse, error)
}

func (m *mockHandler) HandleCertRequest(ctx context.Context, req *server.CertRequest) (*server.CertResponse, error) {
	if m.handleCertRequest != nil {
		return m.handleCertRequest(ctx, req)
	}
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemFailure}
}

func (m *mockHandler) HandleCertConfirm(ctx context.Context, confirm *server.CertConfirmation) error {
	if m.handleCertConfirm != nil {
		return m.handleCertConfirm(ctx, confirm)
	}
	return nil
}

func (m *mockHandler) HandlePollRequest(ctx context.Context, poll *server.PollRequest) (*server.CertResponse, error) {
	if m.handlePollRequest != nil {
		return m.handlePollRequest(ctx, poll)
	}
	return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemFailure}
}

// staticMACLookup implements server.SecretLookup with a fixed secret.
type staticMACLookup struct {
	secret []byte
}

func (l *staticMACLookup) LookupSecret(senderKID []byte) ([]byte, error) {
	return l.secret, nil
}

// emptySecretLookup returns an empty secret to trigger the "invalid secret" path.
type emptySecretLookup struct{}

func (l *emptySecretLookup) LookupSecret(senderKID []byte) ([]byte, error) {
	return []byte{}, nil
}

// failingLookup returns an error from LookupSecret.
type failingLookup struct{}

func (l *failingLookup) LookupSecret(senderKID []byte) ([]byte, error) {
	return nil, assert.AnError
}

// staticCertLookup implements server.CertificateLookup returning a fixed certificate.
type staticCertLookup struct {
	cert *x509.Certificate
}

func (l *staticCertLookup) LookupCertificate(sender pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return l.cert, nil
}

// failingCertLookup returns an error (unknown sender).
type failingCertLookup struct{}

func (l *failingCertLookup) LookupCertificate(sender pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return nil, assert.AnError
}

// issueCert creates a certificate signed by the CA for the given request.
func issueCert(ca *certyaml.Certificate, req *server.CertRequest) *x509.Certificate {
	caCert, _ := ca.X509Certificate()
	caKey, _ := ca.PrivateKey()

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, &caCert, req.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// testSender is the default sender name used in MAC-protected test messages.
var testSender = pkix.Name{CommonName: "test"}

// macMessageOpts returns MessageOptions with a directoryName sender for MAC tests.
func macMessageOpts() pkicmp.MessageOptions {
	return pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryName(testSender.ToRDNSequence()),
	}
}

// protectMAC sets senderKID and applies MAC protection to a message.
func protectMAC(msg *pkicmp.PKIMessage, secret []byte) {
	msg.Header.SenderKID = []byte(testSender.String())
	_ = msg.ProtectWithMAC(secret)
}