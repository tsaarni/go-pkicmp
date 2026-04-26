package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	"github.com/tsaarni/go-pkicmp/client"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func TestCAPubsTrustBootstrap(t *testing.T) {
	recipient := pkix.Name{CommonName: "target-ca"}

	targetCA := &certyaml.Certificate{Subject: "cn=target-ca"}
	targetCACert, _ := targetCA.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: targetCA}
	eeCert, _ := ee.X509Certificate()

	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var respMsg *pkicmp.PKIMessage
		if callCount == 1 {
			ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				CAPubs: []pkicmp.CMPCertificate{{Raw: targetCACert.Raw}},
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
					},
				}},
			})
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: ipBody,
			}
			protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
			_ = respMsg.Protect(protector)
		} else {
			confBody, _ := pkicmp.NewPKIConfBody()
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: confBody,
			}
			protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
			_ = respMsg.Protect(protector)
		}

		der, _ := respMsg.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))

	// No pre-configured roots: trust is bootstrapped from caPubs via PBM (RFC 9810 §5.3.2).
	// The PBM shared secret authenticates the sender as an authorized trust anchor source (§8.9).
	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	assert.NoError(t, err)
}

func TestCAPubsRejectsMismatchedIssuer(t *testing.T) {
	recipient := pkix.Name{CommonName: "target-ca"}

	wrongCA := &certyaml.Certificate{Subject: "cn=malicious-ca"}
	wrongCACert, _ := wrongCA.X509Certificate()

	targetCA := &certyaml.Certificate{Subject: "cn=target-ca"}
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: targetCA}
	eeCert, _ := ee.X509Certificate()

	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var respMsg *pkicmp.PKIMessage
		if callCount == 1 {
			ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				CAPubs: []pkicmp.CMPCertificate{{Raw: wrongCACert.Raw}},
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
					},
				}},
			})
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: ipBody,
			}
			protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
			_ = respMsg.Protect(protector)
		} else {
			confBody, _ := pkicmp.NewPKIConfBody()
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: confBody,
			}
			protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
			_ = respMsg.Protect(protector)
		}

		der, _ := respMsg.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))

	// caPubs contains wrongCA but the EE cert is issued by targetCA.
	// Trust verification fails because the issued cert doesn't chain to the caPubs CA.
	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify certificate trust")
}

func TestResponseValidationRejectsMismatchedTransactionID(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: []byte("evil-transaction-id"),
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
		_ = resp.Protect(protector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL)
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transaction ID mismatch")
}

func TestResponseValidationRejectsMismatchedNonce(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    []byte("evil-nonce"),
			},
			Body: ipBody,
		}
		protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
		_ = resp.Protect(protector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL)
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recipient nonce mismatch")
}

func TestResponseValidationRejectsInvalidMAC(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
		_ = resp.Protect(protector)
		resp.Protection[0] ^= 0xFF // Tamper with MAC
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL)
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify protection: pkicmp: PBM verification failed")
}

func TestResponseValidationRejectsInvalidSignature(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverKey := serverTLS.PrivateKey.(crypto.Signer)
	serverX509, _ := serverCert.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: serverX509.Raw})
		protector, _ := pkicmp.NewSignatureProtector(serverKey, &serverX509)
		_ = resp.Protect(protector)
		resp.Protection[0] ^= 0xFF // Tamper with signature
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	roots := x509.NewCertPool()
	caCert, _ := ca.X509Certificate()
	roots.AddCert(&caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(roots))
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify protection: pkicmp: signature verification failed")
}

func TestResponseValidationRejectsUntrustedCA(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	otherCA := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherEE := &certyaml.Certificate{Subject: "cn=other-ee", Issuer: otherCA}
	otherEECert, _ := otherEE.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: otherEECert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
		_ = resp.Protect(protector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	roots := x509.NewCertPool()
	caCert, _ := ca.X509Certificate()
	roots.AddCert(&caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(roots))
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify certificate trust: x509: certificate signed by unknown authority")
}

func TestResponseValidationRejectsSignatureWithoutTrustedCAs(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverKey := serverTLS.PrivateKey.(crypto.Signer)
	serverX509, _ := serverCert.X509Certificate()
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: serverX509.Raw})
		protector, _ := pkicmp.NewSignatureProtector(serverKey, &serverX509)
		_ = resp.Protect(protector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	// RFC 9810 §8.9: Signature-protected responses require pre-configured roots.
	// Omitting WithTrustedCAs() must produce an error.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL)
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature-protected response requires trusted CAs")
}

func TestResponseValidationRejectsPBMResponseWithoutSecret(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverKey := serverTLS.PrivateKey.(crypto.Signer)
	serverX509, _ := serverCert.X509Certificate()
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		// Server responds with PBM protection.
		pbmProtector, _ := pkicmp.NewDefaultPBMProtector([]byte("server-secret"))
		_ = resp.Protect(pbmProtector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	// Client uses signature protector (no shared secret).
	// Receiving a PBM-protected response must fail because the client
	// cannot verify the MAC without a shared secret.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	roots := x509.NewCertPool()
	caCert, _ := ca.X509Certificate()
	roots.AddCert(&caCert)
	sigProtector, _ := pkicmp.NewSignatureProtector(serverKey, &serverX509)
	c := client.NewClient(server.URL, client.WithTrustedCAs(roots))
	_, err := c.SendIR(context.Background(), key, sigProtector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response uses MAC protection but request protector does not provide shared secret")
}

func TestResponseValidationRejectsMismatchedSenderKID(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=validation-root-ca"}
	caCert, _ := ca.X509Certificate()

	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverKey := serverTLS.PrivateKey.(crypto.Signer)
	serverX509, _ := serverCert.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: ca}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)
		ipBody, _ := pkicmp.NewIPBody(&pkicmp.CertRepMessage{
			Response: []pkicmp.CertResponse{{
				CertReqID: 0,
				Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
				CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
					CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
				},
			}},
		})
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				Sender:        pkicmp.NewDirectoryName(pkix.Name{CommonName: "cmp-server"}.ToRDNSequence()),
				SenderKID:     []byte("wrong-sender-kid"),
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: ipBody,
		}
		resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: serverX509.Raw})
		sigProtector, _ := pkicmp.NewSignatureProtector(serverKey, &serverX509)
		_ = resp.Protect(sigProtector)
		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	roots := x509.NewCertPool()
	roots.AddCert(&caCert)

	c := client.NewClient(
		server.URL,
		client.WithTrustedCAs(roots),
		client.WithRecipient(pkix.Name{CommonName: "cmp-server"}),
	)
	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify protection: pkicmp: signature verification failed")
}

func TestResponseValidationRejectsOversizedHTTPResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(make([]byte, 129))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(128))

	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response body too large")
}

func TestResponseValidationCustomResponseLimitAllowsSmallResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write([]byte{0x00})
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	protector, _ := pkicmp.NewDefaultPBMProtector([]byte("secret"))
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(1024))

	_, err := c.SendIR(context.Background(), key, protector, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "response body too large")
}
