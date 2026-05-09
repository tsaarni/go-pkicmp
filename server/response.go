package server

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// buildResponse creates a protected response message with proper header management.
// RFC 9810 §5.1.1: echo transactionID, senderNonce→recipNonce, fresh senderNonce.
func (s *Server) buildResponse(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity) *pkicmp.PKIMessage {
	return s.buildResponseWithInfo(req, body, sender, nil)
}

// buildResponseWithInfo creates a protected response with optional generalInfo
// included before protection is applied.
func (s *Server) buildResponseWithInfo(req *pkicmp.PKIMessage, body *pkicmp.PKIBody, sender *SenderIdentity, generalInfo []pkicmp.InfoTypeAndValue) *pkicmp.PKIMessage {
	senderNonce := make([]byte, 16)
	_, _ = rand.Read(senderNonce)

	senderName := pkicmp.GeneralName{}
	if len(s.cfg.sender.CommonName) > 0 || len(s.cfg.sender.Organization) > 0 {
		senderName = pkicmp.NewDirectoryName(s.cfg.sender.ToRDNSequence())
	} else if s.cfg.signerCert != nil {
		senderName = pkicmp.NewDirectoryName(s.cfg.signerCert.Subject.ToRDNSequence())
	}

	resp := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			PVNO:          req.Header.PVNO,
			Sender:        senderName,
			Recipient:     req.Header.Sender,
			MessageTime:   time.Now(),
			TransactionID: req.Header.TransactionID,
			SenderNonce:   senderNonce,
			RecipNonce:    req.Header.SenderNonce,
			GeneralInfo:   generalInfo,
		},
		Body: body,
	}

	// RFC 9810 §5.1.1: Set SenderKID in responses.
	if s.cfg.signerCert != nil {
		resp.Header.SenderKID = s.cfg.signerCert.SubjectKeyId
	} else if sender != nil && sender.MACVerified {
		resp.Header.SenderKID = sender.SenderKID
	}

	// Add configured extra certs.
	for _, c := range s.cfg.extraCerts {
		resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: c.Raw})
	}

	// Protection failure is non-fatal; unprotected error responses are acceptable per RFC 9810 §5.3.21.
	_ = s.protectResponse(resp, sender)

	return resp
}

// buildErrorResponse creates an error response message.
func (s *Server) buildErrorResponse(req *pkicmp.PKIMessage, si pkicmp.PKIStatusInfo) *pkicmp.PKIMessage {
	return s.buildResponse(req, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: si}), nil)
}

// buildCertRepResponse creates a CertRepMessage response matching the request type.
func (s *Server) buildCertRepResponse(req *pkicmp.PKIMessage, certReqID int64, si pkicmp.PKIStatusInfo, cert *x509.Certificate, caCerts []*x509.Certificate, sender *SenderIdentity) *pkicmp.PKIMessage {
	reqType := RequestType(req.Body.Type & 0x1f)
	return s.buildCertRepResponseForType(req, certReqID, si, cert, caCerts, sender, reqType)
}

// buildCertRepResponseForType creates a CertRepMessage with the specified response type.
func (s *Server) buildCertRepResponseForType(req *pkicmp.PKIMessage, certReqID int64, si pkicmp.PKIStatusInfo, cert *x509.Certificate, caCerts []*x509.Certificate, sender *SenderIdentity, reqType RequestType) *pkicmp.PKIMessage {
	certResp := pkicmp.CertResponse{
		CertReqID: certReqID,
		Status:    si,
	}

	if cert != nil && si.Status == pkicmp.StatusAccepted {
		certResp.CertifiedKeyPair = &pkicmp.CertifiedKeyPair{
			CertOrEncCert: pkicmp.CertOrEncCert{
				Certificate: &pkicmp.CMPCertificate{Raw: cert.Raw},
			},
		}
	}

	rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{certResp}}

	// Add caPubs.
	for _, ca := range caCerts {
		rep.CAPubs = append(rep.CAPubs, pkicmp.CMPCertificate{Raw: ca.Raw})
	}

	// Select response body type: ir→ip, cr→cp, kur→kup, p10cr→cp.
	var body *pkicmp.PKIBody
	switch reqType {
	case RequestIR:
		body = pkicmp.NewIPBody(rep)
	case RequestKUR:
		body = pkicmp.NewKUPBody(rep)
	default:
		body = pkicmp.NewCPBody(rep)
	}

	// RFC 9810 §5.1.1.1: If the request contains id-it-implicitConfirm in
	// generalInfo, echo it back to skip the certConf/pkiConf exchange.
	// RFC 9810 §5.1.1.2: Otherwise include confirmWaitTime if configured.
	var generalInfo []pkicmp.InfoTypeAndValue
	if si.Status == pkicmp.StatusAccepted && requestHasImplicitConfirm(req) {
		generalInfo = append(generalInfo, pkicmp.InfoTypeAndValue{
			InfoType: pkicmp.OIDImplicitConfirm,
		})
	} else if s.cfg.confirmWait > 0 && si.Status == pkicmp.StatusAccepted {
		derBytes, err := asn1.Marshal(time.Now().Add(s.cfg.confirmWait))
		if err == nil {
			generalInfo = append(generalInfo, pkicmp.InfoTypeAndValue{
				InfoType:  pkicmp.OIDConfirmWaitTime,
				InfoValue: derBytes,
			})
		}
	}

	return s.buildResponseWithInfo(req, body, sender, generalInfo)
}

// requestHasImplicitConfirm checks if the request contains id-it-implicitConfirm
// in the PKIHeader generalInfo field (RFC 9810 §5.1.1.1).
func requestHasImplicitConfirm(req *pkicmp.PKIMessage) bool {
	for _, gi := range req.Header.GeneralInfo {
		if gi.InfoType.Equal(pkicmp.OIDImplicitConfirm) {
			return true
		}
	}
	return false
}
