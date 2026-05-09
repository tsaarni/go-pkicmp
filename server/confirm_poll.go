package server

import (
	"bytes"
	"context"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// handleCertConf processes certConf messages (RFC 9810 §5.3.18).
func (s *Server) handleCertConf(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	conf, err := msg.Body.CertConf()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// Look up the issued cert entry for this transaction.
	txID := string(msg.Header.TransactionID)
	v, exists := s.issuedCerts.Load(txID)
	if !exists {
		// No pending transaction — reject.
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"unknown transaction"},
		})
	}
	entry := v.(issuedCertEntry)

	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	if len(msg.Header.RecipNonce) == 0 {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !bytes.Equal(msg.Header.RecipNonce, entry.senderNonce) {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}

	// RFC 9483 §3.5: senderNonce MUST be fresh (different from previous message).
	// The previous message's senderNonce is now our recipNonce, so check against that.
	if bytes.Equal(msg.Header.SenderNonce, entry.senderNonce) {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadSenderNonce,
			StatusString: pkicmp.PKIFreeText{"senderNonce reused"},
		})
	}

	// certConf MUST NOT be signed with the newly issued certificate (security best practice).
	// Only check if both certs have SubjectKeyId set.
	if sender != nil && sender.Certificate != nil && entry.cert != nil {
		if len(sender.Certificate.SubjectKeyId) > 0 && len(entry.cert.SubjectKeyId) > 0 {
			if bytes.Equal(sender.Certificate.SubjectKeyId, entry.cert.SubjectKeyId) {
				return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
					Status:       pkicmp.StatusRejection,
					FailInfo:     pkicmp.FailBadMessageCheck,
					StatusString: pkicmp.PKIFreeText{"certConf signed with newly issued certificate"},
				})
			}
		}
	}

	confirmation := &CertConfirmation{
		TransactionID: msg.Header.TransactionID,
		Sender:        sender,
		Raw:           msg,
	}

	// RFC 9810 §5.3.18: omission of CertStatus = rejection.
	if len(*conf) == 0 {
		confirmation.Rejected = []int64{0}
	} else {
		for _, cs := range *conf {
			accepted := true
			// Verify certHash against issued certificate.
			if entry.cert != nil {
				hash := pkicmp.HashFromSigAlg(entry.cert.SignatureAlgorithm)
				if hash != 0 {
					h := hash.New()
					h.Write(entry.cert.Raw)
					expected := h.Sum(nil)
					if !bytes.Equal(cs.CertHash, expected) {
						accepted = false
					}
				}
			}
			if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusRejection {
				accepted = false
			}
			if accepted {
				confirmation.Accepted = append(confirmation.Accepted, cs.CertReqID)
			} else {
				confirmation.Rejected = append(confirmation.Rejected, cs.CertReqID)
			}
		}
	}

	// Clean up stored cert and transaction.
	s.issuedCerts.Delete(txID)
	s.pendingRequests.Delete(txID)
	s.activeTransactions.Delete(txID)

	_ = s.handler.HandleCertConfirm(ctx, confirmation)

	return s.buildResponse(msg, pkicmp.NewPKIConfBody(), sender)
}

// handlePollReq processes pollReq messages (RFC 9810 §5.3.22).
func (s *Server) handlePollReq(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
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

	// Look up original request type.
	var origReqType RequestType
	if v, ok := s.pendingRequests.Load(string(msg.Header.TransactionID)); ok {
		origReqType = v.(pendingEntry).reqType
	}

	poll := &PollRequest{
		TransactionID:   msg.Header.TransactionID,
		CertReqID:       certReqID,
		OriginalRequest: origReqType,
		Sender:          sender,
		Raw:             msg,
	}

	resp, err := s.handler.HandlePollRequest(ctx, poll)
	if err != nil {
		si := errorToStatusInfo(err)
		return s.buildErrorResponse(msg, si)
	}

	// Still waiting → respond with PollRep.
	if resp.Waiting != nil {
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
	respMsg := s.buildCertRepResponseForType(msg, certReqID, si, resp.Certificate, resp.CACerts, sender, origReqType)

	if resp.Certificate != nil {
		s.issuedCerts.Store(string(msg.Header.TransactionID), issuedCertEntry{
			cert:        resp.Certificate,
			senderNonce: respMsg.Header.SenderNonce,
			createdAt:   time.Now(),
		})
	}
	return respMsg
}

