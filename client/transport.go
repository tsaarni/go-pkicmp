package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func (c *Client) enroll(ctx context.Context, reqBody *pkicmp.PKIBody, expectedRepType pkicmp.BodyType, protector pkicmp.Protector, opts *requestOptions) (*EnrollResult, error) {
	transactionID := make([]byte, 16)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, fmt.Errorf("cmp: generate transaction ID: %w", err)
	}

	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, fmt.Errorf("cmp: generate sender nonce: %w", err)
	}

	sender := pkicmp.GeneralName{}
	if opts.sender != nil {
		sender = pkicmp.NewDirectoryName((*opts.sender).ToRDNSequence())
	}

	recipient := pkicmp.GeneralName{}
	if len(c.recipient.Names) > 0 || len(c.recipient.ExtraNames) > 0 {
		recipient = pkicmp.NewDirectoryName(c.recipient.ToRDNSequence())
	}

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			Sender:        sender,
			Recipient:     recipient,
			MessageTime:   time.Now(),
			TransactionID: transactionID,
			SenderNonce:   senderNonce,
		},
		Body: reqBody,
	}

	for _, cert := range c.extraCerts {
		msg.ExtraCerts = append(msg.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
	}

	if err := msg.Protect(protector); err != nil {
		return nil, fmt.Errorf("cmp: protect request: %w", err)
	}

	reqDER, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal request: %w", err)
	}

	respDER, err := c.sendHTTP(ctx, reqDER)
	if err != nil {
		return nil, err
	}

	resp, err := pkicmp.ParsePKIMessage(respDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse response: %w", err)
	}

	if err := c.verifyResponse(msg, resp, protector, c.trustedCAs); err != nil {
		return nil, fmt.Errorf("cmp: verify response: %w", err)
	}

	if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
		return nil, fmt.Errorf("cmp: unsupported protocol version: %d", resp.Header.PVNO)
	}

	if resp.Body.Type == pkicmp.BodyTypeError {
		return nil, parseErrorResponse(resp)
	}

	if resp.Body.Type != expectedRepType {
		return nil, fmt.Errorf("cmp: unexpected response body type: %d", resp.Body.Type)
	}

	certResp, caPubs, err := extractCertRespAndCAPubs(resp, expectedRepType)
	if err != nil {
		return nil, err
	}

	if certResp.Status.Status == pkicmp.StatusWaiting {
		resp, err = c.poll(ctx, msg.Header, resp, protector, certResp.CertReqID)
		if err != nil {
			return nil, err
		}
		certResp, caPubs, err = extractCertRespAndCAPubs(resp, expectedRepType)
		if err != nil {
			return nil, err
		}
	}

	if certResp.Status.Status != pkicmp.StatusAccepted && certResp.Status.Status != pkicmp.StatusGrantedWithMods {
		return nil, certResp.Status.AsError()
	}

	cert, err := extractCertificate(certResp)
	if err != nil {
		return nil, err
	}

	// Build effective trust pool: start with pre-configured roots, add any
	// caPubs bootstrapped via PBM (RFC 9810 §5.3.2).
	effectiveRoots := c.trustedCAs
	if isPBMProtector(protector) {
		effectiveRoots = addCAPubsToPool(effectiveRoots, caPubs)
	}

	// RFC 9810 §8.9: Verify the issued certificate against trusted CAs.
	if effectiveRoots != nil {
		verifyOpts := x509.VerifyOptions{
			Roots:     effectiveRoots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, fmt.Errorf("verify certificate trust: %w", err)
		}
	}

	var parsedCACerts []*x509.Certificate
	for _, certPub := range caPubs {
		if pc, err := certPub.Parse(); err == nil {
			parsedCACerts = append(parsedCACerts, pc)
		}
	}

	var parsedExtraCerts []*x509.Certificate
	for _, extraCert := range resp.ExtraCerts {
		if pc, err := extraCert.Parse(); err == nil {
			parsedExtraCerts = append(parsedExtraCerts, pc)
		}
	}

	certHash := sha256.Sum256(cert.Raw)
	certStatus := pkicmp.CertStatus{
		CertHash:  certHash[:],
		CertReqID: certResp.CertReqID,
	}

	newSenderNonce := make([]byte, 16)
	if _, err := rand.Read(newSenderNonce); err != nil {
		return nil, fmt.Errorf("cmp: generate sender nonce: %w", err)
	}

	confBody, err := pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{certStatus})
	if err != nil {
		return nil, err
	}

	confMsg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			Sender:        sender,
			Recipient:     recipient,
			MessageTime:   time.Now(),
			TransactionID: transactionID,
			SenderNonce:   newSenderNonce,
			RecipNonce:    resp.Header.SenderNonce,
		},
		Body: confBody,
	}

	if err := confMsg.Protect(protector); err != nil {
		return nil, fmt.Errorf("cmp: protect certConf: %w", err)
	}

	confDER, err := confMsg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal certConf: %w", err)
	}

	confRespDER, err := c.sendHTTP(ctx, confDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: certConf exchange: %w", err)
	}

	// RFC 9810 §5.3.18: The server MUST respond with PKIConf.
	confResp, err := pkicmp.ParsePKIMessage(confRespDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse PKIConf: %w", err)
	}

	if err := c.verifyResponse(confMsg, confResp, protector, effectiveRoots); err != nil {
		return nil, fmt.Errorf("cmp: verify PKIConf: %w", err)
	}

	if confResp.Body.Type == pkicmp.BodyTypeError {
		return nil, parseErrorResponse(confResp)
	}

	if confResp.Body.Type != pkicmp.BodyTypePKIConf {
		return nil, fmt.Errorf("cmp: expected PKIConf but got body type %d", confResp.Body.Type)
	}

	return &EnrollResult{
		Certificate:       cert,
		CAPubs:            parsedCACerts,
		ExtraCertificates: parsedExtraCerts,
	}, nil
}

func extractCertRespAndCAPubs(resp *pkicmp.PKIMessage, expectedRepType pkicmp.BodyType) (*pkicmp.CertResponse, []pkicmp.CMPCertificate, error) {
	var rep *pkicmp.CertRepMessage
	var err error

	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		rep, err = resp.Body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = resp.Body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = resp.Body.KUP()
	default:
		return nil, nil, fmt.Errorf("cmp: unsupported expected response type %d", expectedRepType)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(rep.Response) == 0 {
		return nil, nil, fmt.Errorf("cmp: empty response")
	}
	return &rep.Response[0], rep.CAPubs, nil
}

func (c *Client) sendHTTP(ctx context.Context, reqDER []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("cmp: create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/pkixcmp")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cmp: HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	readBody := io.Reader(resp.Body)
	if c.maxResponseBytes > 0 {
		// RFC 9810 §8.9 emphasizes robust verification; cap message size to limit
		// resource exhaustion from malformed or malicious servers.
		readBody = io.LimitReader(resp.Body, c.maxResponseBytes+1)
	}

	body, err := io.ReadAll(readBody)
	if err != nil {
		return nil, fmt.Errorf("cmp: read response: %w", err)
	}
	if c.maxResponseBytes > 0 && int64(len(body)) > c.maxResponseBytes {
		return nil, fmt.Errorf("cmp: response body too large: limit=%d", c.maxResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cmp: HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return body, nil
}

func parseErrorResponse(msg *pkicmp.PKIMessage) error {
	errContent, err := msg.Body.Error()
	if err != nil {
		return fmt.Errorf("cmp: error parsing ErrorMsgContent: %w", err)
	}
	return errContent.PKIStatusInfo.AsError()
}

func extractCertificate(resp *pkicmp.CertResponse) (*x509.Certificate, error) {
	if resp.CertifiedKeyPair == nil {
		return nil, fmt.Errorf("cmp: missing certifiedKeyPair in response")
	}
	cert := resp.CertifiedKeyPair.CertOrEncCert.Certificate
	if cert == nil {
		return nil, fmt.Errorf("cmp: encrypted certificates not yet supported")
	}

	return cert.Parse()
}

func (c *Client) poll(ctx context.Context, origHeader pkicmp.PKIHeader, lastResp *pkicmp.PKIMessage, protector pkicmp.Protector, certReqID int64) (*pkicmp.PKIMessage, error) {
	var waitTime time.Duration

	for i := 0; i < c.maxPolls; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitTime):
			}
		}

		pollReq := pkicmp.PollReqContent{certReqID}
		body, err := pkicmp.NewPollReqBody(&pollReq)
		if err != nil {
			return nil, err
		}

		newSenderNonce := make([]byte, 16)
		if _, err := rand.Read(newSenderNonce); err != nil {
			return nil, fmt.Errorf("cmp: generate sender nonce: %w", err)
		}

		pollMsg := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				Sender:        origHeader.Sender,
				Recipient:     origHeader.Recipient,
				MessageTime:   time.Now(),
				TransactionID: origHeader.TransactionID,
				SenderNonce:   newSenderNonce,
				RecipNonce:    lastResp.Header.SenderNonce,
			},
			Body: body,
		}

		if err := pollMsg.Protect(protector); err != nil {
			return nil, fmt.Errorf("cmp: protect poll request: %w", err)
		}

		pollDER, err := pollMsg.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("cmp: marshal poll request: %w", err)
		}

		respDER, err := c.sendHTTP(ctx, pollDER)
		if err != nil {
			return nil, err
		}

		resp, err := pkicmp.ParsePKIMessage(respDER)
		if err != nil {
			return nil, fmt.Errorf("cmp: parse polled response: %w", err)
		}

		if err := c.verifyResponse(pollMsg, resp, protector, c.trustedCAs); err != nil {
			return nil, fmt.Errorf("cmp: verify polled response: %w", err)
		}

		if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
			return nil, fmt.Errorf("cmp: unsupported protocol version: %d", resp.Header.PVNO)
		}

		if resp.Body.Type == pkicmp.BodyTypeError {
			return nil, parseErrorResponse(resp)
		}

		if resp.Body.Type == pkicmp.BodyTypePollRep {
			pollRep, err := resp.Body.PollRep()
			if err != nil {
				return nil, err
			}
			if len(*pollRep) > 0 {
				waitTime = time.Duration((*pollRep)[0].CheckAfter) * time.Second
			}
			lastResp = resp
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("cmp: polling exceeded max retries (%d)", c.maxPolls)
}

func (c *Client) verifyResponse(req *pkicmp.PKIMessage, resp *pkicmp.PKIMessage, protector pkicmp.Protector, trustedCAs *x509.CertPool) error {
	if !bytes.Equal(resp.Header.TransactionID, req.Header.TransactionID) {
		return fmt.Errorf("transaction ID mismatch")
	}

	if !bytes.Equal(resp.Header.RecipNonce, req.Header.SenderNonce) {
		return fmt.Errorf("recipient nonce mismatch")
	}

	if resp.Header.ProtectionAlg == nil {
		return fmt.Errorf("missing protection algorithm in response")
	}

	// NOTE: Do NOT compare resp.Header.Sender against c.recipient here.
	// RFC 9810 §5.1.1 defines the sender field as a hint to locate the
	// verification key, not as an identity that must match the request's
	// recipient. The response sender is the CA/RA's own name, which may
	// legitimately differ from the recipient the client addressed (e.g.,
	// RA-forwarded requests, or CAs using a separate CMP signing identity).
	// Authenticity is established by verifying the protection: signature
	// chain against trusted roots (§8.9), or MAC via shared secret.

	verifier, err := pkicmp.ProtectionVerifier(*resp.Header.ProtectionAlg)
	if err != nil {
		return fmt.Errorf("get verifier: %w", err)
	}

	if sv, ok := verifier.(pkicmp.SignatureVerifier); ok {
		// RFC 9810 §8.9: When authenticating signature-protected messages,
		// the end entity MUST use existing trust anchors. Require WithTrustedCAs()
		// to be configured so the signer's certificate can be verified.
		if trustedCAs == nil {
			return fmt.Errorf("signature-protected response requires trusted CAs: use WithTrustedCAs()")
		}
		// Include extra certs from response for verification.
		sv.SetTrustedCerts(resp.ExtraCerts)
		sv.SetTrustPool(trustedCAs)

		if skb, ok := verifier.(interface{ SetExpectedSenderKID([]byte) }); ok {
			skb.SetExpectedSenderKID(resp.Header.SenderKID)
		}
	}

	if mv, ok := verifier.(pkicmp.MACVerifier); ok {
		if mp, ok := protector.(pkicmp.MACProtector); ok {
			mv.SetSharedSecret(mp.SharedSecret())
		} else {
			return fmt.Errorf("response uses MAC protection but request protector does not provide shared secret")
		}
	}

	if err := resp.Verify(verifier); err != nil {
		return fmt.Errorf("verify protection: %w", err)
	}

	return nil
}

// addCAPubsToPool returns a CertPool containing roots plus any parsed caPubs certificates.
// RFC 9810 §5.3.2: If the message protection is "shared secret information",
// then any certificate transported in the caPubs field may be directly trusted
// as a root CA certificate by the initiator.
func addCAPubsToPool(roots *x509.CertPool, caPubs []pkicmp.CMPCertificate) *x509.CertPool {
	if len(caPubs) == 0 {
		return roots
	}
	// Clone existing roots or create a new pool.
	var pool *x509.CertPool
	if roots != nil {
		pool = roots.Clone()
	} else {
		pool = x509.NewCertPool()
	}
	for _, cert := range caPubs {
		pc, err := cert.Parse()
		if err != nil {
			continue
		}
		pool.AddCert(pc)
	}
	return pool
}

// isPBMProtector returns true if the protector uses Password-Based MAC.
func isPBMProtector(protector pkicmp.Protector) bool {
	_, ok := protector.(pkicmp.MACProtector)
	return ok
}
