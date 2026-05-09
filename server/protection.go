package server

import (
	"crypto/x509/pkix"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// verifyProtection verifies message protection and returns the sender identity.
func (s *Server) verifyProtection(msg *pkicmp.PKIMessage) (*SenderIdentity, error) {
	if msg.Header.ProtectionAlg == nil || len(msg.Protection) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "message not protected"}
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// MAC-protected message.
	if alg.Equal(pkicmp.OIDPasswordBasedMac) {
		if s.cfg.secretLookup == nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC protection not configured"}
		}
		secret, err := s.cfg.secretLookup.LookupSecret(msg.Header.SenderKID)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "unknown sender"}
		}
		creds, err := pkicmp.NewMACCredentials(secret)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "invalid secret"}
		}
		_, err = msg.Verify(pkicmp.VerifyOptions{Credentials: creds})
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC verification failed"}
		}
		return &SenderIdentity{SenderKID: msg.Header.SenderKID, MACVerified: true}, nil
	}

	// Signature-protected message.
	if s.cfg.certificateLookup == nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "signature protection not configured"}
	}

	// Resolve sender DN from header.
	var senderName pkix.Name
	if len(msg.Header.Sender.DirectoryName) > 0 {
		senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
	}

	// Look up the sender's certificate from the server's database.
	// RFC 9810 §5.1.1: senderKID SHOULD be used but is not mandatory.
	signerCert, err := s.cfg.certificateLookup.LookupCertificate(senderName, msg.Header.SenderKID)
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "unknown sender"}
	}

	// Verify signature directly against the looked-up certificate.
	// No chain validation needed — the server trusts this certificate
	// because it came from its own database.
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert})
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "signature verification failed"}
	}

	return &SenderIdentity{Certificate: signerCert}, nil
}

// protectResponse applies protection to the response message.
func (s *Server) protectResponse(resp *pkicmp.PKIMessage, sender *SenderIdentity) error {
	// MAC-protected request → MAC-protect response with same secret.
	if sender != nil && sender.MACVerified && s.cfg.secretLookup != nil {
		secret, err := s.cfg.secretLookup.LookupSecret(sender.SenderKID)
		if err == nil && len(secret) > 0 {
			return resp.ProtectWithMAC(secret)
		}
	}

	// Signature protection.
	if s.cfg.signerKey != nil && s.cfg.signerCert != nil {
		return resp.ProtectWithSignature(s.cfg.signerKey, s.cfg.signerCert, s.cfg.signerChain...)
	}

	return nil
}
