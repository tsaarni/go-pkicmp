package server

import (
	"context"
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

// handleCertRequestNew processes cert requests via the new Handler interface.
func (s *Server) handleCertRequestNew(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	credID, err := sender.CredentialID()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID

	// RFC 9810 §5.1.1: Reject if transactionID is already pending (waiting for poll).
	if _, exists := s.getPending(credID, txnID); exists {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailTransactionIdInUse,
		})
	}

	// Determine certReqID for response building.
	certReqID := certReqIDFromRequest(msg)
	reqType := requestTypeFromBody(msg.Body.Type)

	// Call handler.
	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		return s.buildCertRepResponseForType(msg, certReqID, si, nil, nil, sender, reqType)
	}

	// Waiting response → store request type and pollRef for polling.
	if resp.Waiting != nil {
		s.setPending(credID, txnID, reqType, resp.Waiting.PollRef)
		si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}
		return s.buildCertRepResponseForType(msg, certReqID, si, nil, nil, sender, reqType)
	}

	// Certificate issued.
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	respMsg := s.buildCertRepResponseForType(msg, certReqID, si, resp.Certificate, resp.CACerts, sender, reqType)

	if resp.Certificate != nil {
		s.setIssued(credID, txnID, resp.Certificate, respMsg.Header.SenderNonce)
	}

	return respMsg
}

// handlePollReqNew processes poll requests via the new Handler interface.
func (s *Server) handlePollReqNew(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	pollReq, err := msg.Body.PollReq()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	var certReqID int64
	if len(*pollReq) > 0 {
		certReqID = (*pollReq)[0]
	}

	credID, err := sender.CredentialID()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID

	// Look up pending request using composite key — automatically rejects different credentials.
	pending, ok := s.getPending(credID, txnID)
	if !ok {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"no pending certificate"},
		})
	}

	// Pass pollRef to handler via context.
	ctx = contextWithPollRef(ctx, pending.pollRef)

	// Call handler.
	resp, err := s.handler.HandleCMP(ctx, msg, sender)
	if err != nil {
		si := errorToStatusInfo(err)
		return s.buildErrorResponse(msg, si)
	}

	// Still waiting → update pollRef and respond with PollRep.
	if resp.Waiting != nil {
		s.setPending(credID, txnID, pending.reqType, resp.Waiting.PollRef)
		checkAfter := int64(resp.Waiting.CheckAfter / time.Second)
		if checkAfter < 1 {
			checkAfter = 1
		}
		item := pkicmp.PollRepItem{CertReqID: certReqID, CheckAfter: checkAfter}
		if resp.Waiting.Reason != "" {
			item.Reason = pkicmp.PKIFreeText{resp.Waiting.Reason}
		}
		pollRep := pkicmp.PollRepContent{item}
		return s.buildResponse(msg, pkicmp.NewPollRepBody(&pollRep), sender)
	}

	// Certificate ready → respond with ip/cp/kup matching original request type.
	si := pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	respMsg := s.buildCertRepResponseForType(msg, certReqID, si, resp.Certificate, resp.CACerts, sender, pending.reqType)

	if resp.Certificate != nil {
		s.setIssued(credID, txnID, resp.Certificate, respMsg.Header.SenderNonce)
	}
	return respMsg
}

// certReqIDFromRequest extracts the certReqID from a cert request message.
func certReqIDFromRequest(msg *pkicmp.PKIMessage) int64 {
	if msg.Body.Type == pkicmp.BodyTypeP10CR {
		return -1
	}
	crmf, err := parseCRMFMsg(msg)
	if err != nil {
		return 0
	}
	return crmf.certReqID
}

// requestTypeFromBody maps a body type to a RequestType.
func requestTypeFromBody(bodyType pkicmp.BodyType) RequestType {
	switch bodyType {
	case pkicmp.BodyTypeIR:
		return RequestIR
	case pkicmp.BodyTypeCR:
		return RequestCR
	case pkicmp.BodyTypeKUR:
		return RequestKUR
	case pkicmp.BodyTypeP10CR:
		return RequestP10CR
	default:
		return RequestType(bodyType & 0x1f)
	}
}
