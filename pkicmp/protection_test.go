package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func TestPBMRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	protector, err := pkicmp.NewPBMProtector(
		secret,
		salt,
		1024,
		pkicmp.OIDSHA256,
		pkicmp.OIDHMACWithSHA256,
	)
	require.NoError(t, err)

	body, err := pkicmp.NewPKIConfBody()
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			TransactionID: []byte("trans-1"),
		},
		Body: body,
	}

	err = msg.Protect(protector)
	require.NoError(t, err)

	// Verify protection algorithm is set correctly
	assert.Equal(t, pkicmp.OIDPasswordBasedMac, msg.Header.ProtectionAlg.Algorithm)

	// Round-trip through marshaling
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// Verify using Verifier
	verifier, err := pkicmp.ProtectionVerifier(*parsed.Header.ProtectionAlg)
	require.NoError(t, err)

	macVerifier, ok := verifier.(pkicmp.MACVerifier)
	require.True(t, ok)
	macVerifier.SetSharedSecret(secret)

	err = parsed.Verify(macVerifier)
	assert.NoError(t, err)

	// Verify with wrong secret fails
	macVerifier.SetSharedSecret([]byte("wrong-secret"))
	err = parsed.Verify(macVerifier)
	assert.Error(t, err)
}

func TestSignatureRoundTrip(t *testing.T) {
	// 1. Setup keys and cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// 2. Setup protector
	protector, err := pkicmp.NewSignatureProtector(priv, cert)
	require.NoError(t, err)

	body, err := pkicmp.NewPKIConfBody()
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			TransactionID: []byte("trans-sig"),
		},
		Body: body,
	}

	err = msg.Protect(protector)
	require.NoError(t, err)

	// 3. Marshal and Parse
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// 4. Verify
	verifier, err := pkicmp.ProtectionVerifier(*parsed.Header.ProtectionAlg)
	require.NoError(t, err)

	sigVerifier, ok := verifier.(pkicmp.SignatureVerifier)
	require.True(t, ok)
	sigVerifier.SetTrustedCerts([]pkicmp.CMPCertificate{{Raw: cert.Raw}})

	err = parsed.Verify(sigVerifier)
	assert.NoError(t, err)
}
