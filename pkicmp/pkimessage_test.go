package pkicmp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func TestP10CRRoundTrip(t *testing.T) {
	// 1. Create a CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test User",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// 2. Build PKIMessage
	body, err := pkicmp.NewP10CRBody(csr)
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			Sender:    pkicmp.NewDirectoryName(pkix.RDNSequence{{{Type: []int{2, 5, 4, 3}, Value: "Sender"}}}),
			Recipient: pkicmp.NewDirectoryName(pkix.RDNSequence{{{Type: []int{2, 5, 4, 3}, Value: "Recipient"}}}),
			TransactionID: []byte("trans-123"),
			SenderNonce:    []byte("nonce-123"),
		},
		Body: body,
	}

	// 3. Marshal
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	// 4. Parse
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// 5. Verify fields
	assert.Equal(t, pkicmp.PVNO2, parsed.Header.PVNO) // Should default to v2 for p10cr
	assert.Equal(t, []byte("trans-123"), parsed.Header.TransactionID)
	assert.Equal(t, pkicmp.BodyTypeP10CR, parsed.Body.Type)

	parsedCSR, err := parsed.Body.P10CR()
	require.NoError(t, err)
	assert.Equal(t, csr.Subject.String(), parsedCSR.Subject.String())
	assert.Equal(t, csr.Raw, parsedCSR.Raw)
}

func TestPVNO3Trigger(t *testing.T) {
	// hashAlg in certConf triggers PVNO3
	conf := pkicmp.NewCertConfirmContent(
		pkicmp.NewCertStatusWithHashAlg([]byte("hash"), 123, &pkicmp.AlgorithmIdentifier{Algorithm: pkicmp.OIDSHA256}),
	)
	body, err := pkicmp.NewCertConfBody(conf)
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			Sender:    pkicmp.NewDirectoryName(pkix.RDNSequence{}),
			Recipient: pkicmp.NewDirectoryName(pkix.RDNSequence{}),
		},
		Body: body,
	}

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	assert.Equal(t, pkicmp.PVNO3, parsed.Header.PVNO)

	gotConf, err := parsed.Body.CertConf()
	require.NoError(t, err)
	assert.Len(t, *gotConf, 1)
	assert.Equal(t, pkicmp.OIDSHA256, (*gotConf)[0].HashAlg.Algorithm)
}
