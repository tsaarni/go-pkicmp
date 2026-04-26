package client

import (
	"context"
	"crypto/x509"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// SendP10CR sends a PKCS#10 CSR to the CA.
// The message envelope must be protected by the provided pkicmp.Protector.
// - For initial enrollment, use pkicmp.NewDefaultPBMProtector(...)
// - For key updates/renewals, use pkicmp.NewSignatureProtector(...)
func (c *Client) SendP10CR(ctx context.Context, csrDER []byte, protector pkicmp.Protector, opts ...RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}

	body, err := pkicmp.NewP10CRBody(csr)
	if err != nil {
		return nil, err
	}

	return c.enroll(ctx, body, pkicmp.BodyTypeCP, protector, ropts)
}
