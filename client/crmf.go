package client

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// SendIR performs an Initialization Request.
// Typically protected by a shared-secret MAC (pkicmp.NewDefaultPBMProtector).
func (c *Client) SendIR(ctx context.Context, key crypto.Signer, protector pkicmp.Protector, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, protector, pkicmp.BodyTypeIP, opts)
}

// SendCR performs a Certification Request for an additional certificate.
// Typically protected by an existing certificate's signature (pkicmp.NewSignatureProtector).
func (c *Client) SendCR(ctx context.Context, key crypto.Signer, protector pkicmp.Protector, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, protector, pkicmp.BodyTypeCP, opts)
}

// SendKUR performs a Key Update Request.
// Typically protected by an existing certificate's signature (pkicmp.NewSignatureProtector).
func (c *Client) SendKUR(ctx context.Context, newKey crypto.Signer, protector pkicmp.Protector, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, newKey, protector, pkicmp.BodyTypeKUP, opts)
}

func (c *Client) sendCRMF(ctx context.Context, key crypto.Signer, protector pkicmp.Protector, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal public key: %w", err)
	}

	tmpl := pkicmp.CertTemplate{
		PublicKey: pubDER,
	}

	if ropts.templateSubject != nil {
		tmpl.Subject = pkicmp.NewDirectoryName((*ropts.templateSubject).ToRDNSequence())
	}

	if len(ropts.templateExts) > 0 {
		extDER, err := asn1.Marshal(ropts.templateExts)
		if err != nil {
			return nil, fmt.Errorf("cmp: marshal extensions: %w", err)
		}
		tmpl.Extensions = extDER
	}

	certReq := pkicmp.CertRequest{
		CertReqID:    0,
		CertTemplate: tmpl,
	}

	certReqMsg := pkicmp.CertReqMsg{
		CertReq: certReq,
	}

	if err := certReqMsg.GeneratePOP(key); err != nil {
		return nil, fmt.Errorf("cmp: generate POP: %w", err)
	}

	reqs := pkicmp.CertReqMessages{certReqMsg}
	var body *pkicmp.PKIBody
	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		body, err = pkicmp.NewIRBody(&reqs)
	case pkicmp.BodyTypeCP:
		body, err = pkicmp.NewCRBody(&reqs)
	case pkicmp.BodyTypeKUP:
		body, err = pkicmp.NewKURBody(&reqs)
	default:
		return nil, fmt.Errorf("cmp: unsupported CRMF expected response type %d", expectedRepType)
	}
	if err != nil {
		return nil, err
	}

	return c.enroll(ctx, body, expectedRepType, protector, ropts)
}
