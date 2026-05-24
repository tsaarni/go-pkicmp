package server

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/tsaarni/go-pkicmp/pkicmp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// macRequestParams holds the echoed MAC parameters extracted from a client request.
// Used to apply matching protection to the response.
type macRequestParams struct {
	algorithm      asn1.ObjectIdentifier
	iterationCount int
	keyLength      int
	owf            asn1.ObjectIdentifier
	mac            asn1.ObjectIdentifier
	owfParameters  []byte
	macParameters  []byte
}

// verifyProtection verifies message protection and returns the sender identity.
func (s *Server) verifyProtection(msg *pkicmp.PKIMessage) (*SenderIdentity, error) {
	if msg.Header.ProtectionAlg == nil || len(msg.Protection) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "message not protected"}
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// MAC-protected message.
	if isMACAlgorithm(alg) {
		if s.cfg.secretLookup == nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC protection not configured"}
		}

		// Resolve sender DN from header (may be NULL-DN for initial enrollment).
		var senderName pkix.Name
		if len(msg.Header.Sender.DirectoryName) > 0 {
			senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
		}

		secret, err := s.cfg.secretLookup.LookupSecret(senderName, msg.Header.SenderKID)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "unknown sender"}
		}
		creds, _ := pkicmp.NewMACCredentials(secret)
		_, err = msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
		_ = creds // silence unused warning
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC verification failed"}
		}
		return &SenderIdentity{Sender: senderName, SenderKID: msg.Header.SenderKID, MACVerified: true, secret: secret}, nil
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

	// Resolve issuer from recipient header field.
	var issuerName pkix.Name
	if len(msg.Header.Recipient.DirectoryName) > 0 {
		issuerName.FillFromRDNSequence(&msg.Header.Recipient.DirectoryName)
	}

	// Look up the sender's certificate from the server's database.
	// RFC 9810 §5.1.1: senderKID SHOULD be used but is not mandatory.
	signerCert, err := s.cfg.certificateLookup.LookupCertificate(issuerName, senderName, msg.Header.SenderKID)
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

	return &SenderIdentity{Certificate: signerCert, Sender: senderName}, nil
}

// isMACAlgorithm returns true if the OID is a supported MAC protection algorithm.
func isMACAlgorithm(oid asn1.ObjectIdentifier) bool {
	// OIDPasswordBasedMac = 1.2.840.113533.7.66.13
	// OIDPBMAC1 = 1.2.840.113549.1.5.14
	return oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}) ||
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14})
}

// oidPBMAC1 is the OID for PBMAC1.
var oidPBMAC1server = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

// oidPasswordBasedMac is the OID for PasswordBasedMac.
var oidPasswordBasedMacServer = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}

// oidPBKDF2Server is the OID for PBKDF2.
var oidPBKDF2server = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

// protectResponseWithOptions applies protection using stored MAC options when available.
func (s *Server) protectResponseWithOptions(resp *pkicmp.PKIMessage, sender *SenderIdentity, macOpts *macRequestParams) error {
	// MAC-protected request → MAC-protect response with same secret.
	if sender != nil && sender.MACVerified && len(sender.secret) > 0 {
		secret := sender.secret
		var opts []pkicmp.MACCredentialOption
		if macOpts != nil {
			opts = append(opts, pkicmp.WithMACAlgorithm(macOpts.algorithm))
			if macOpts.iterationCount != 0 {
				opts = append(opts, pkicmp.WithMACIterationCount(macOpts.iterationCount))
			}
			if macOpts.keyLength != 0 {
				opts = append(opts, pkicmp.WithMACKeyLength(macOpts.keyLength))
			}
			if macOpts.owf != nil {
				opts = append(opts, pkicmp.WithMAC_OWF(macOpts.owf))
			}
			if macOpts.mac != nil {
				opts = append(opts, pkicmp.WithMAC_MAC(macOpts.mac))
			}
			if len(macOpts.owfParameters) > 0 {
				opts = append(opts, pkicmp.WithMACOWFParameters(macOpts.owfParameters))
			}
			if len(macOpts.macParameters) > 0 {
				opts = append(opts, pkicmp.WithMACMACParameters(macOpts.macParameters))
			}
		}
		creds, err := pkicmp.NewMACCredentials(secret, opts...)
		if err != nil {
			return err
		}
		return creds.Protect(resp)
	}

	// Signature protection.
	if s.cfg.signerKey != nil && s.cfg.signerCert != nil {
		creds, err := pkicmp.NewSignatureCredentials(s.cfg.signerKey, s.cfg.signerCert, s.cfg.signerChain...)
		if err != nil {
			return err
		}
		return creds.Protect(resp)
	}

	return nil
}

// extractMACOptions extracts PBM/PBMAC1 parameters from a MAC-protected request message.
// Returns nil if the message is not MAC-protected or parameters cannot be parsed.
func extractMACOptions(msg *pkicmp.PKIMessage) *macRequestParams {
	if msg.Header.ProtectionAlg == nil {
		return nil
	}
	if len(msg.Header.ProtectionAlg.Parameters) == 0 {
		return nil
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// RFC 8018 §7.1: PBMAC1 parameters.
	if alg.Equal(oidPBMAC1server) {
		return extractPBMAC1Options(msg.Header.ProtectionAlg.Parameters)
	}

	if !alg.Equal(oidPasswordBasedMacServer) {
		return nil
	}

	// Parse PBMParameter from the protectionAlg parameters.
	s := cryptobyte.String(msg.Header.ProtectionAlg.Parameters)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil
	}
	// Skip salt (OCTET STRING).
	var salt []byte
	if !seq.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) {
		return nil
	}
	// Read OWF AlgorithmIdentifier.
	var owfSeq cryptobyte.String
	if !seq.ReadASN1(&owfSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var owfOID asn1.ObjectIdentifier
	if !owfSeq.ReadASN1ObjectIdentifier(&owfOID) {
		return nil
	}
	// Capture any remaining parameters (e.g., NULL).
	var owfParams []byte
	if !owfSeq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if owfSeq.ReadAnyASN1Element(&params, &tag) {
			owfParams = params
		}
	}
	// Read iterationCount.
	var iterCount int64
	if !seq.ReadASN1Integer(&iterCount) {
		return nil
	}
	// Read MAC AlgorithmIdentifier.
	var macSeq cryptobyte.String
	if !seq.ReadASN1(&macSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var macOID asn1.ObjectIdentifier
	if !macSeq.ReadASN1ObjectIdentifier(&macOID) {
		return nil
	}
	// Capture any remaining parameters (e.g., NULL).
	var macParams []byte
	if !macSeq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if macSeq.ReadAnyASN1Element(&params, &tag) {
			macParams = params
		}
	}

	return &macRequestParams{
		algorithm:      oidPasswordBasedMacServer,
		iterationCount: int(iterCount),
		owf:            owfOID,
		mac:            macOID,
		owfParameters:  owfParams,
		macParameters:  macParams,
	}
}

// extractPBMAC1Options parses PBMAC1-params (RFC 8018 §A.4) from protectionAlg parameters.
// PBMAC1-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, messageAuthScheme AlgorithmIdentifier }
func extractPBMAC1Options(params []byte) *macRequestParams {
	s := cryptobyte.String(params)
	var outer cryptobyte.String
	if !s.ReadASN1(&outer, cbasn1.SEQUENCE) {
		return nil
	}

	// keyDerivationFunc AlgorithmIdentifier (OID = id-PBKDF2).
	var kdfSeq cryptobyte.String
	if !outer.ReadASN1(&kdfSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var kdfOID asn1.ObjectIdentifier
	if !kdfSeq.ReadASN1ObjectIdentifier(&kdfOID) {
		return nil
	}
	if !kdfOID.Equal(oidPBKDF2server) {
		return nil
	}

	// PBKDF2-params: SEQUENCE { salt, iterationCount, [keyLength], [prf] }
	var pbkdf2Params cryptobyte.String
	if !kdfSeq.ReadASN1(&pbkdf2Params, cbasn1.SEQUENCE) {
		return nil
	}
	// Skip salt (OCTET STRING).
	var salt []byte
	if !pbkdf2Params.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) {
		return nil
	}
	// Read iterationCount.
	var iterCount int64
	if !pbkdf2Params.ReadASN1Integer(&iterCount) {
		return nil
	}
	// Skip optional keyLength (INTEGER) if present, then read prf.
	// RFC 8018 §A.2: keyLength is OPTIONAL INTEGER, prf is OPTIONAL SEQUENCE.
	var keyLength int64
	prfOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9} // default: hmacWithSHA256
	if !pbkdf2Params.Empty() {
		var peek cryptobyte.String
		var tag cbasn1.Tag
		if !pbkdf2Params.ReadAnyASN1Element(&peek, &tag) {
			return nil
		}
		if tag == cbasn1.INTEGER {
			// Was keyLength; parse its value.
			inner := cryptobyte.String(peek)
			if !inner.ReadASN1Integer(&keyLength) {
				return nil
			}
			// Read prf if present.
			if !pbkdf2Params.Empty() {
				var prfSeq cryptobyte.String
				if pbkdf2Params.ReadASN1(&prfSeq, cbasn1.SEQUENCE) {
					prfSeq.ReadASN1ObjectIdentifier(&prfOID)
				}
			}
		} else if tag == cbasn1.SEQUENCE {
			// Was prf directly (no keyLength).
			inner := cryptobyte.String(peek)
			var prfSeq cryptobyte.String
			if inner.ReadASN1(&prfSeq, cbasn1.SEQUENCE) {
				prfSeq.ReadASN1ObjectIdentifier(&prfOID)
			}
		}
	}

	// messageAuthScheme AlgorithmIdentifier.
	var macSeq cryptobyte.String
	if !outer.ReadASN1(&macSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var macOID asn1.ObjectIdentifier
	if !macSeq.ReadASN1ObjectIdentifier(&macOID) {
		return nil
	}

	return &macRequestParams{
		algorithm:      oidPBMAC1server,
		iterationCount: int(iterCount),
		keyLength:      int(keyLength),
		owf:            prfOID,
		mac:            macOID,
	}
}
