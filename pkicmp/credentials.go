package pkicmp

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Credentials is the interface representing material used to protect a CMP message.
// The library provides [MACCredentials] and [SignatureCredentials], but custom
// implementations are possible for hardware tokens, testing, or non-standard schemes.
type Credentials interface {
	// Protect applies protection to the message.
	Protect(msg *PKIMessage) error
}

// MACCredentialOption is a functional option for [NewMACCredentials].
type MACCredentialOption func(*macCredentialConfig)

type macCredentialConfig struct {
	algorithm      asn1.ObjectIdentifier
	iterationCount int
	owf            asn1.ObjectIdentifier
	mac            asn1.ObjectIdentifier
	keyLength      int
	owfParameters  []byte
	macParameters  []byte
}

// WithMACAlgorithm sets the top-level MAC algorithm OID (oidPasswordBasedMac or oidPBMAC1).
func WithMACAlgorithm(oid asn1.ObjectIdentifier) MACCredentialOption {
	return func(c *macCredentialConfig) { c.algorithm = oid }
}

// WithMACIterationCount sets the PBKDF iteration count.
func WithMACIterationCount(n int) MACCredentialOption {
	return func(c *macCredentialConfig) { c.iterationCount = n }
}

// WithMAC_OWF sets the one-way function (OWF) algorithm OID for PBM.
func WithMAC_OWF(oid asn1.ObjectIdentifier) MACCredentialOption { //nolint:revive
	return func(c *macCredentialConfig) { c.owf = oid }
}

// WithMAC_MAC sets the MAC algorithm OID.
func WithMAC_MAC(oid asn1.ObjectIdentifier) MACCredentialOption { //nolint:revive
	return func(c *macCredentialConfig) { c.mac = oid }
}

// WithMACKeyLength sets the derived key length (PBMAC1 only).
func WithMACKeyLength(n int) MACCredentialOption {
	return func(c *macCredentialConfig) { c.keyLength = n }
}

// WithMACOWFParameters sets the raw ASN.1 OWF parameters to echo verbatim.
func WithMACOWFParameters(p []byte) MACCredentialOption {
	return func(c *macCredentialConfig) { c.owfParameters = p }
}

// WithMACMACParameters sets the raw ASN.1 MAC parameters to echo verbatim.
func WithMACMACParameters(p []byte) MACCredentialOption {
	return func(c *macCredentialConfig) { c.macParameters = p }
}

// MACCredentials holds a shared secret for Password-Based MAC protection.
// Create with [NewMACCredentials].
//
// Callers should set Header.SenderKID before calling Protect to identify the
// shared secret to the recipient (RFC 9810 §5.1.1).
type MACCredentials struct {
	secret []byte
	cfg    macCredentialConfig
}

// NewMACCredentials creates credentials for shared-secret (PBM or PBMAC1) protection.
// Returns an error if the secret is empty.
// The secret is copied — the caller may safely mutate the original slice after this call.
// By default, PBM (oidPasswordBasedMac) with standard defaults is used.
// Use [WithMACAlgorithm], [WithMACIterationCount], etc. to override.
func NewMACCredentials(secret []byte, opts ...MACCredentialOption) (*MACCredentials, error) {
	if len(secret) == 0 {
		return nil, &ProtectionError{Reason: ReasonMissingSharedSecret}
	}
	s := make([]byte, len(secret))
	copy(s, secret)
	c := &MACCredentials{secret: s}
	for _, opt := range opts {
		opt(&c.cfg)
	}
	return c, nil
}

func (c *MACCredentials) Protect(msg *PKIMessage) error {
	alg := c.cfg.algorithm
	if alg == nil {
		alg = oidPasswordBasedMac
	}
	if alg.Equal(oidPBMAC1) {
		return msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:         c.secret,
			IterationCount: c.cfg.iterationCount,
			KeyLength:      c.cfg.keyLength,
			PRF:            c.cfg.owf,
			MAC:            c.cfg.mac,
		})
	}
	return msg.protectWithMACOptions(macOptions{
		Secret:         c.secret,
		Algorithm:      alg,
		IterationCount: c.cfg.iterationCount,
		OWF:            c.cfg.owf,
		MAC:            c.cfg.mac,
		OWFParameters:  c.cfg.owfParameters,
		MACParameters:  c.cfg.macParameters,
	})
}

// SharedSecret returns the shared secret held by this credentials object.
// This is used internally by the server to protect responses with the same secret.
func (c *MACCredentials) SharedSecret() []byte {
	return c.secret
}

// SignatureCredentials holds a signing key and certificate for signature-based
// protection. Create with [NewSignatureCredentials].
type SignatureCredentials struct {
	key   crypto.Signer
	cert  *x509.Certificate
	chain []*x509.Certificate // optional intermediate certificates
}

// NewSignatureCredentials creates credentials for certificate-based signature
// protection. Returns an error if key is nil, cert is nil, or the key does not
// match the certificate's public key.
func NewSignatureCredentials(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) (*SignatureCredentials, error) {
	if key == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner}
	}
	if cert == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner, Err: fmt.Errorf("certificate is nil")}
	}
	pubDER, err1 := x509.MarshalPKIXPublicKey(key.Public())
	certPubDER, err2 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(pubDER, certPubDER) != 1 {
		return nil, &ProtectionError{Reason: ReasonMissingSigner, Err: fmt.Errorf("private key does not match certificate public key")}
	}
	return &SignatureCredentials{key: key, cert: cert, chain: chain}, nil
}

// Certificate returns the signing certificate.
func (c *SignatureCredentials) Certificate() *x509.Certificate {
	return c.cert
}

func (c *SignatureCredentials) Protect(msg *PKIMessage) error {
	return msg.protectWithSignature(c.key, c.cert, c.chain...)
}

