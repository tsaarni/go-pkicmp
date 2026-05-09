//go:build integration

package cmptestsuite

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tsaarni/go-pkicmp/internal/mockserver"
	"github.com/tsaarni/go-pkicmp/server"
)

const sharedSecret = "test-shared-secret"

func TestCMPTestSuite(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH")
	}

	port := startMockServer(t)

	configDir := renderConfig(t, configData{Port: port})

	reportsDir, err := filepath.Abs("reports")
	require.NoError(t, err)

	t.Logf("running cmp-test-suite against port %d (reports: %s)", port, reportsDir)

	runErr := runCMPTestSuite(t, runOpts{
		ConfigDir:  configDir,
		ReportsDir: reportsDir,
		Tags:       []string{"minimal"},
		Excludes:   []string{"revocation", "kga", "genm", "nested", "pq"},
	})

	t.Log("(test failures from output.xml are listed below)")
	reportResults(t, reportsDir)
	require.NoError(t, runErr, "cmp-test-suite run failed")
}

// startMockServer starts the CMP mock server in a goroutine and returns the port.
func startMockServer(t *testing.T) int {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(newPrefixWriter(os.Stdout, "[mockserver] "), &slog.HandlerOptions{Level: slog.LevelDebug}))

	h, caKey, caCert, err := mockserver.New(mockserver.WithLogger(logger))
	require.NoError(t, err)

	srv := server.New(h,
		server.WithSigner(caKey, caCert),
		server.WithCertificateLookup(h),
		server.WithSecretLookup(server.SecretLookupFunc(func(senderKID []byte) ([]byte, error) {
			// RFC 9810 §5.1.1: senderKID identifies the shared secret.
			// Accept senderKID matching the sender's CN.
			if string(senderKID) != "CN=CMP Client" {
				return nil, fmt.Errorf("unknown senderKID: %s", senderKID)
			}
			return []byte(sharedSecret), nil
		})),
		server.WithExtraCerts([]*x509.Certificate{caCert}),
		server.WithSender(pkix.Name{CommonName: "Test CA"}),
	)

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port

	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { httpSrv.Close() })

	// Wait for readiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return port
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mockserver did not become ready")
	return 0
}
