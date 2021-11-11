package cert_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/sensu/cert-checks/internal/cert"
	"github.com/sensu/cert-checks/internal/cert/testcert"
)

func TestCollectMetricsFromFile(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	testCertPath := tmpDir + "/testcert.pem"
	err := os.WriteFile(testCertPath, testcert.TestCert, 0644)
	if err != nil {
		t.Fatalf("could not write test certificate to file: %v", err)
	}

	corruptedCert := make([]byte, len(testcert.TestCert))
	copy(corruptedCert, testcert.TestCert)
	for i := len(corruptedCert) / 2; i < len(corruptedCert); i += 8 {
		corruptedCert[i] ^= 0xFF
	}
	corruptCertPath := tmpDir + "/bogustestcert.pem"
	err = os.WriteFile(corruptCertPath, corruptedCert, 0644)
	if err != nil {
		t.Fatalf("could not write corrupted test certificate to file: %v", err)
	}

	withTimeIssued := func() time.Time {
		return testcert.NotBefore
	}

	oneHourAfterExpiration := func() time.Time {
		return testcert.NotAfter.Add(time.Hour)
	}

	testCases := []testCase{
		{
			Name: "absolute file path to PEM encoded cert",
			Args: args{
				Cert: testCertPath,
				Now:  withTimeIssued,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(testcert.TimeEffective.Seconds()),
			},
		},
		{
			Name: "file:// prefix for PEM encoded cert",
			Args: args{
				Cert: "file://" + testCertPath,
				Now:  withTimeIssued,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(testcert.TimeEffective.Seconds()),
			},
		},
		{
			Name: "expired PEM encoded cert",
			Args: args{
				Cert: testCertPath,
				Now:  oneHourAfterExpiration,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  int((testcert.TimeEffective + time.Hour).Seconds()),
				SecondsUntilExpires: int((-1 * time.Hour).Seconds()),
			},
		},
		{
			Name: "corrupted PEM file",
			Args: args{
				Cert: corruptCertPath,
				Now:  oneHourAfterExpiration,
			},
			ExpectErr: true,
		},
		{
			Name: "File Not Found",
			Args: args{
				Cert: tmpDir + "/does-not-exist.txt",
			},
			ExpectErr: true,
		},
		{
			Name: "Not a file",
			Args: args{
				Cert: tmpDir,
			},
			ExpectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			actual, err := cert.CollectMetrics(ctx, tc.Args.Cert, cert.Config{Now: tc.Args.Now})
			if err != nil && !tc.ExpectErr {
				t.Errorf("unexpected error %v", err)
				return
			}
			if err != nil {
				return
			}

			if tc.Expected == nil {
				return
			}
			if actual.SecondsSinceIssued != tc.Expected.SecondsSinceIssued {
				t.Errorf("expected SecondsSinceIssued to be: %d. actual: %d", tc.Expected.SecondsSinceIssued, actual.SecondsSinceIssued)
			}
			if actual.SecondsUntilExpires != tc.Expected.SecondsUntilExpires {
				t.Errorf("expected SecondsUntilExpires to be: %d. actual: %d", tc.Expected.SecondsUntilExpires, actual.SecondsUntilExpires)
			}
		})
	}
}

func TestCollectMetricsFromTLS(t *testing.T) {
	ctx := context.Background()

	keyPair, err := tls.X509KeyPair(testcert.TestCert, testcert.TestKey)
	if err != nil {
		t.Fatalf("could not load testcert as x509 key pair: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{keyPair}}
	srv := &http.Server{
		TLSConfig:    tlsCfg,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start test server: %v", err)
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	nonTLSSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
	defer nonTLSSrv.Close()
	withTimeIssued := func() time.Time {
		return testcert.NotBefore
	}

	oneHourAfterExpiration := func() time.Time {
		return testcert.NotAfter.Add(time.Hour)
	}

	testCases := []testCase{
		{
			Name: "https test server",
			Args: args{
				Cert: "https://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  0,
				SecondsUntilExpires: int(testcert.TimeEffective.Seconds()),
			},
		}, {
			Name: "https test server expired",
			Args: args{
				Cert: "https://" + ln.Addr().String(),
				Now:  oneHourAfterExpiration,
			},
			Expected: &cert.Metrics{
				SecondsSinceIssued:  int((testcert.TimeEffective + time.Hour).Seconds()),
				SecondsUntilExpires: int(-1 * time.Hour.Seconds()),
			},
		}, {
			Name: "tcp test server",
			Args: args{
				Cert: "tcp://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
		}, {
			Name: "tcp4 test server",
			Args: args{
				Cert: "tcp4://" + ln.Addr().String(),
				Now:  withTimeIssued,
			},
		}, {
			Name: "non-tls server",
			Args: args{
				Cert: "tcp://" + nonTLSSrv.Listener.Addr().String(),
				Now:  withTimeIssued,
			},
			ExpectErr: true,
		}, {
			Name: "no such host",
			Args: args{
				Cert: "tcp://no.such.host.sensu.io:443",
			},
			ExpectErr: true,
		}, {
			Name: "no response from server",
			Args: args{
				Cert: "tcp://sensu.io:9876",
			},
			ExpectErr: true,
		}, {
			Name: "http not supported",
			Args: args{
				Cert: "http://" + ln.Addr().String(),
			},
			ExpectErr: true,
		}, {
			Name: "udp not supported",
			Args: args{
				Cert: "udp://" + ln.Addr().String(),
			},
			ExpectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			actual, err := cert.CollectMetrics(ctx, tc.Args.Cert, cert.Config{Now: tc.Args.Now})
			if err != nil && !tc.ExpectErr {
				t.Errorf("unexpected error %v", err)
				return
			}
			if err != nil {
				return
			}

			if tc.Expected == nil {
				return
			}
			if actual.SecondsSinceIssued != tc.Expected.SecondsSinceIssued {
				t.Errorf("expected SecondsSinceIssued to be: %d. actual: %d", tc.Expected.SecondsSinceIssued, actual.SecondsSinceIssued)
			}
			if actual.SecondsUntilExpires != tc.Expected.SecondsUntilExpires {
				t.Errorf("expected SecondsUntilExpires to be: %d. actual: %d", tc.Expected.SecondsUntilExpires, actual.SecondsUntilExpires)
			}
		})
	}
}

type args struct {
	Cert string
	Now  func() time.Time
}

type testCase struct {
	Name      string
	Args      args
	Expected  *cert.Metrics
	ExpectErr bool
}
