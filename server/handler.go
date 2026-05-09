package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// Handler processes CMP requests. Implement this to add CMP support to a CA or RA.
//
// The server package handles protocol mechanics: message parsing, protection verification,
// POP validation, and RFC-mandated header checks. Policy decisions are the handler's
// responsibility:
//   - Whether to allow CA certificates (check Extensions for BasicConstraints with cA=true)
//   - Authorization based on sender identity
//   - Certificate profile validation
//   - Rate limiting and other operational policies
//
// Use [HasCABasicConstraints] to check for CA certificate requests.
type Handler interface {
	// HandleCertRequest processes IR, CR, KUR, and P10CR requests.
	// Called after the server has verified message protection, POP, and validated the header.
	// Return an issued certificate, a WaitingResponse for polling, or an error.
	HandleCertRequest(ctx context.Context, req *CertRequest) (*CertResponse, error)

	// HandleCertConfirm is called when the client confirms or rejects a certificate.
	// RFC 9810 §5.3.18: omission of a CertStatus means rejection.
	// The server automatically responds with PKIConf after this returns.
	HandleCertConfirm(ctx context.Context, confirm *CertConfirmation) error

	// HandlePollRequest is called when the client polls for a pending certificate.
	// Return the certificate if ready, or another WaitingResponse with updated checkAfter.
	HandlePollRequest(ctx context.Context, poll *PollRequest) (*CertResponse, error)
}

// RequestType identifies the CMP operation type.
type RequestType int

const (
	RequestIR    RequestType = 0 // Initialization Request
	RequestCR    RequestType = 2 // Certification Request
	RequestP10CR RequestType = 4 // PKCS#10 Certification Request
	RequestKUR   RequestType = 7 // Key Update Request
)

// CertRequest is the parsed, verified enrollment request presented to the Handler.
type CertRequest struct {
	// Type identifies the CMP operation: IR, CR, KUR, or P10CR.
	Type RequestType

	// Subject from the certificate template (CRMF) or CSR (P10CR).
	Subject pkix.Name

	// PublicKey is the requester's public key to be certified.
	PublicKey crypto.PublicKey

	// Extensions requested (SANs, key usage, etc.)
	Extensions []pkix.Extension

	// CertReqID from the CRMF request (always -1 for P10CR per RFC 9810 §5.3.4).
	CertReqID int64

	// Sender is the verified identity from message protection.
	Sender *SenderIdentity

	// TransactionID identifies this enrollment transaction.
	TransactionID []byte

	// CertProfile from the generalInfo header field (RFC 9810 §5.1.1.4), if present.
	CertProfile string

	// Raw provides access to the full PKIMessage for advanced use cases.
	Raw *pkicmp.PKIMessage
}

// SenderIdentity represents the authenticated message sender.
type SenderIdentity struct {
	// Certificate is set when the request was signature-protected.
	Certificate *x509.Certificate
	// SenderKID is the reference number from MAC-protected requests.
	SenderKID []byte
	// MACVerified is true when protection was verified via shared secret.
	MACVerified bool
}

// CertResponse is what the Handler returns.
type CertResponse struct {
	// Certificate is the issued certificate. Mutually exclusive with Waiting.
	Certificate *x509.Certificate
	// CACerts for the caPubs field (RFC 9810 §5.3.4).
	CACerts []*x509.Certificate
	// Waiting signals the CA needs more time. Triggers polling.
	Waiting *WaitingResponse
}

// WaitingResponse tells the server to respond with "waiting" status.
type WaitingResponse struct {
	CheckAfter time.Duration
	Reason     string
}

// PollRequest is presented when the client polls for a pending certificate.
type PollRequest struct {
	TransactionID   []byte
	CertReqID       int64
	OriginalRequest RequestType // The request type that started this transaction
	Sender          *SenderIdentity
	Raw             *pkicmp.PKIMessage
}

// CertConfirmation is presented when the client sends certConf.
type CertConfirmation struct {
	TransactionID []byte
	Sender        *SenderIdentity
	// Accepted contains CertReqIDs that the client confirmed.
	Accepted []int64
	// Rejected contains CertReqIDs that the client rejected.
	Rejected []int64
	Raw      *pkicmp.PKIMessage
}
