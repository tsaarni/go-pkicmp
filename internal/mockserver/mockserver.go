// Package mockserver provides a minimal CMP handler for testing.
package mockserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
	"github.com/tsaarni/go-pkicmp/server"
)

// Handler implements server.Handler by issuing certificates signed by a CA.
// It also implements server.CertificateLookup to allow the server to verify
// signature-protected requests using certificates previously issued by this handler.
type Handler struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	log    *slog.Logger

	// issuedCerts stores all issued certificates.
	mu          sync.Mutex
	issuedCerts []*x509.Certificate
}

// Option configures the Handler.
type Option func(*Handler)

// WithLogger sets the logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(h *Handler) { h.log = l }
}

// New creates a Handler with a self-signed CA.
func New(opts ...Option) (*Handler, *ecdsa.PrivateKey, *x509.Certificate, error) {
	caKey, caCert, err := GenerateCA()
	if err != nil {
		return nil, nil, nil, err
	}
	h := &Handler{caKey: caKey, caCert: caCert, log: slog.Default()}
	for _, o := range opts {
		o(h)
	}
	return h, caKey, caCert, nil
}

func (h *Handler) HandleCertRequest(_ context.Context, req *server.CertRequest) (*server.CertResponse, error) {
	if server.HasCABasicConstraints(req.Extensions) {
		return nil, &server.Error{
			Status:      pkicmp.StatusRejection,
			FailureInfo: pkicmp.FailNotAuthorized,
			StatusText:  "CA certificates not allowed",
		}
	}

	h.log.Info("HandleCertRequest",
		"subject", req.Subject.String(),
		"public_key_type", fmt.Sprintf("%T", req.PublicKey),
		"extensions_count", len(req.Extensions),
	)
	if der, err := req.Raw.MarshalBinary(); err == nil {
		h.log.Debug("HandleCertRequest request DER", "hex", hex.EncodeToString(der))
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Compute SubjectKeyIdentifier from public key per RFC 5280 §4.2.1.2.
	pubDER, err := x509.MarshalPKIXPublicKey(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	ski := sha1.Sum(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         req.Subject,
		Issuer:          h.caCert.Subject,
		NotBefore:       time.Now().Add(-1 * time.Minute),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		SubjectKeyId:    ski[:],
		ExtraExtensions: req.Extensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, h.caCert, req.PublicKey, h.caKey)
	if err != nil {
		h.log.Error("HandleCertRequest failed", "error", err)
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		h.log.Error("HandleCertRequest failed", "error", err)
		return nil, fmt.Errorf("parsing issued certificate: %w", err)
	}

	h.log.Info("HandleCertRequest issued",
		"serial", cert.SerialNumber.String(),
		"subject", cert.Subject.String(),
	)

	// Store for later lookup (signature-protected requests).
	h.mu.Lock()
	h.issuedCerts = append(h.issuedCerts, cert)
	h.mu.Unlock()

	return &server.CertResponse{Certificate: cert}, nil
}

// LookupCertificate implements server.CertificateLookup by finding a previously
// issued certificate by SubjectKeyId.
func (h *Handler) LookupCertificate(sender pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(senderKID) == 0 {
		return nil, fmt.Errorf("senderKID required")
	}

	for _, cert := range h.issuedCerts {
		if len(cert.SubjectKeyId) > 0 && bytes.Equal(cert.SubjectKeyId, senderKID) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("no certificate found for senderKID %x", senderKID)
}

func (h *Handler) HandleCertConfirm(_ context.Context, conf *server.CertConfirmation) error {
	h.log.Info("HandleCertConfirm", "accepted", conf.Accepted, "rejected", conf.Rejected)
	if der, err := conf.Raw.MarshalBinary(); err == nil {
		h.log.Debug("HandleCertConfirm request DER", "hex", hex.EncodeToString(der))
	}
	return nil
}

func (h *Handler) HandlePollRequest(_ context.Context, poll *server.PollRequest) (*server.CertResponse, error) {
	h.log.Info("HandlePollRequest", "cert_req_id", poll.CertReqID)
	if der, err := poll.Raw.MarshalBinary(); err == nil {
		h.log.Debug("HandlePollRequest request DER", "hex", hex.EncodeToString(der))
	}
	return nil, fmt.Errorf("no pending certificate")
}

// GenerateCA creates a self-signed ECDSA P-256 CA certificate.
func GenerateCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	// Compute SubjectKeyIdentifier as SHA-1 of the public key per RFC 5280 §4.2.1.2.
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	ski := sha1.Sum(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski[:],
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}
