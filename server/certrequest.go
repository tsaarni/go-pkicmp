package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// handleCertRequest processes ir, cr, kur, p10cr messages.
func (s *Server) handleCertRequest(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	// RFC 9810 §5.1.1: Reject if transactionID is already in use.
	if _, exists := s.pendingRequests.Load(string(msg.Header.TransactionID)); exists {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailTransactionIdInUse,
		})
	}

	var reqType RequestType
	var certReqID int64
	var subject pkix.Name
	var pubKey crypto.PublicKey
	var extensions []pkix.Extension

	switch msg.Body.Type {
	case pkicmp.BodyTypeP10CR:
		reqType = RequestP10CR
		// RFC 9810 §5.3.4: certReqId MUST be -1 for P10CR.
		certReqID = -1
		csr, err := msg.Body.P10CR()
		if err != nil {
			return s.buildCertRepResponse(msg, certReqID, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
			}, nil, nil, sender)
		}
		// RFC 4211 §4: Verify CSR signature (Proof of Possession).
		if err := csr.CheckSignature(); err != nil {
			return s.buildCertRepResponse(msg, certReqID, pkicmp.PKIStatusInfo{
				Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadPOP,
			}, nil, nil, sender)
		}
		subject = csr.Subject
		pubKey = csr.PublicKey
		extensions = csr.Extensions
	default:
		reqType = RequestType(msg.Body.Type & 0x1f) // strip class bits
		crmf, err := s.parseCRMF(msg)
		if err != nil {
			failInfo := pkicmp.FailBadDataFormat
			statusText := err.Error()
			var srvErr *Error
			if errors.As(err, &srvErr) {
				failInfo = srvErr.FailureInfo
				statusText = srvErr.StatusText
			}
			return s.buildCertRepResponseForType(msg, certReqID, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     failInfo,
				StatusString: pkicmp.PKIFreeText{statusText},
			}, nil, nil, sender, reqType)
		}
		certReqID = crmf.certReqID
		subject = crmf.subject
		pubKey = crmf.publicKey
		extensions = crmf.extensions

		// Verify POP.
		if err := s.verifyPOP(msg); err != nil {
			failInfo := pkicmp.FailBadPOP
			// RFC 9810 §5.2.8.1: An end entity MUST NOT use raVerified.
			var parseErr *pkicmp.ParseError
			if errors.As(err, &parseErr) && parseErr.Detail == "raVerified POP not supported" {
				failInfo = pkicmp.FailNotAuthorized
			}
			return s.buildCertRepResponseForType(msg, certReqID, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     failInfo,
				StatusString: pkicmp.PKIFreeText{err.Error()},
			}, nil, nil, sender, reqType)
		}

		// RFC 9483 §5.1.1: POP MUST be present unless central key generation is requested.
		if crmf.popRequired && crmf.popMissing {
			return s.buildCertRepResponseForType(msg, certReqID, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadPOP,
				StatusString: pkicmp.PKIFreeText{"POP required for signature key"},
			}, nil, nil, sender, reqType)
		}
	}

	// RFC 9483 §4.1.1: Subject MUST be present in certTemplate.
	if len(subject.String()) == 0 {
		return s.buildCertRepResponseForType(msg, certReqID, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadCertTemplate,
			StatusString: pkicmp.PKIFreeText{"subject required"},
		}, nil, nil, sender, reqType)
	}

	certReq := &CertRequest{
		Type:          reqType,
		Subject:       subject,
		PublicKey:     pubKey,
		Extensions:    extensions,
		CertReqID:     certReqID,
		Sender:        sender,
		TransactionID: msg.Header.TransactionID,
		CertProfile:   msg.Header.CertProfile(),
		Raw:           msg,
	}

	resp, err := s.handler.HandleCertRequest(ctx, certReq)
	if err != nil {
		si := errorToStatusInfo(err)
		return s.buildCertRepResponse(msg, certReqID, si, nil, nil, sender)
	}

	// Waiting response → store request type for polling.
	if resp.Waiting != nil {
		s.pendingRequests.Store(string(msg.Header.TransactionID), pendingEntry{
			reqType:   reqType,
			createdAt: time.Now(),
		})
		si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}
		return s.buildCertRepResponse(msg, certReqID, si, nil, nil, sender)
	}

	// Store issued cert for certHash verification.
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	respMsg := s.buildCertRepResponse(msg, certReqID, si, resp.Certificate, resp.CACerts, sender)

	if resp.Certificate != nil {
		s.issuedCerts.Store(string(msg.Header.TransactionID), issuedCertEntry{
			cert:        resp.Certificate,
			senderNonce: respMsg.Header.SenderNonce,
			createdAt:   time.Now(),
		})
	}

	return respMsg
}

type parsedCRMF struct {
	certReqID   int64
	subject     pkix.Name
	publicKey   crypto.PublicKey
	extensions  []pkix.Extension
	popMissing  bool // POP not present in request
	popRequired bool // Key type requires POP (signature-capable)
}

// parseCRMF extracts fields from a CRMF request body.
func (s *Server) parseCRMF(msg *pkicmp.PKIMessage) (*parsedCRMF, error) {
	var msgs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		msgs, err = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		msgs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		msgs, err = msg.Body.KUR()
	default:
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	}
	if err != nil {
		return nil, err
	}
	if len(*msgs) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat, StatusText: "empty CertReqMessages"}
	}
	if len(*msgs) > 1 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "multiple CertReqMsg not supported"}
	}

	reqMsg := (*msgs)[0]
	result := &parsedCRMF{certReqID: reqMsg.CertReq.CertReqID}

	// Extract subject.
	if len(reqMsg.CertReq.CertTemplate.Subject.DirectoryName) > 0 {
		var name pkix.Name
		name.FillFromRDNSequence(&reqMsg.CertReq.CertTemplate.Subject.DirectoryName)
		result.subject = name
	}

	// Extract public key.
	if len(reqMsg.CertReq.CertTemplate.PublicKey) > 0 {
		pub, err := x509.ParsePKIXPublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg, StatusText: err.Error()}
		}
		result.publicKey = pub

		// Check if key type requires POP (signature-capable keys).
		result.popRequired = isSignatureCapableKey(pub)
	}

	// Check if POP is missing.
	result.popMissing = reqMsg.Popo == nil || reqMsg.Popo.Signature == nil

	// Extract extensions.
	if len(reqMsg.CertReq.CertTemplate.Extensions) > 0 {
		var exts []pkix.Extension
		rest := reqMsg.CertReq.CertTemplate.Extensions
		// Parse DER SEQUENCE OF Extension using encoding/asn1.
		if _, err := asn1.Unmarshal(rest, &exts); err != nil {
			return nil, err
		}
		result.extensions = exts
	}

	return result, nil
}

// verifyPOP verifies the Proof of Possession for CRMF requests.
// RFC 4211 §4: Delegates to pkicmp.VerifyPOP.
func (s *Server) verifyPOP(msg *pkicmp.PKIMessage) error {
	var msgs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		msgs, err = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		msgs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		msgs, err = msg.Body.KUR()
	default:
		return nil
	}
	if err != nil || len(*msgs) == 0 {
		return err
	}

	return pkicmp.VerifyPOP(&(*msgs)[0])
}

// isSignatureCapableKey returns true if the key can be used for signing.
// RSA, ECDSA, and EdDSA keys are signature-capable.
func isSignatureCapableKey(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

// HasCABasicConstraints checks if extensions contain BasicConstraints with cA=true.
// Handlers can use this to reject CA certificate requests as a policy decision.
func HasCABasicConstraints(extensions []pkix.Extension) bool {
	// OID for BasicConstraints: 2.5.29.19
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}

	for _, ext := range extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return true
			}
		}
	}
	return false
}

