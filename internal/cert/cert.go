package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const secondsToDays = float64(60 * 60 * 24)

type Metrics struct {
	EvaluatedAt         time.Time
	SecondsSinceIssued  int
	SecondsUntilExpires int
}

func (m Metrics) Output() string {
	epoch := m.EvaluatedAt.UnixMilli()
	lines := []string{
		"# TYPE cert_days_left gauge",
		fmt.Sprintf("cert_days_left %f %d", float64(m.SecondsUntilExpires)/secondsToDays, epoch),
		"# TYPE cert_seconds_left gauge",
		fmt.Sprintf("cert_seconds_left %d %d", m.SecondsUntilExpires, epoch),
		"# TYPE cert_issued_days counter",
		fmt.Sprintf("cert_issued_days %f %d", float64(m.SecondsSinceIssued)/secondsToDays, epoch),
		"# TYPE cert_issued_seconds counter",
		fmt.Sprintf("cert_issued_seconds %d %d", m.SecondsSinceIssued, epoch),
	}
	return strings.Join(lines, "\n")
}

// Config for evaluating metrics
type Config struct {
	// Now provider defaults to time.Now() when not provided
	Now func() time.Time
}

// CollectMetrics Loads a certificate at a particular location and
func CollectMetrics(ctx context.Context, path string, cfg Config) (Metrics, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var metrics Metrics
	certLoader, err := parse(path)
	if err != nil {
		return metrics, fmt.Errorf("error parsing cert location: %v", err)
	}
	cert, err := certLoader(ctx)
	if err != nil {
		return metrics, err
	}
	now := cfg.Now()
	metrics.EvaluatedAt = now
	metrics.SecondsSinceIssued = int(now.Sub(cert.NotBefore).Seconds())
	metrics.SecondsUntilExpires = int(cert.NotAfter.Sub(now).Seconds())
	return metrics, nil
}

func parse(cert string) (certificateLoader, error) {
	certURL, err := url.Parse(cert)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL %v", err)
	}
	switch certURL.Scheme {
	case "", "file":
		info, err := os.Stat(certURL.Path)
		if err != nil {
			return nil, fmt.Errorf("file not found: %s", certURL.Path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("cannot use directory: %s", certURL.Path)
		}
		return fromFile(certURL.Path), nil
	case "https", "tcp", "tcp4", "tcp6":
		if certURL.Scheme == "https" {
			certURL.Scheme = "tcp"
			if certURL.Port() == "" {
				certURL.Host = fmt.Sprintf("%s:443", certURL.Host)
			}
		}
		return fromTLSHandshake(certURL), nil
	default:
		return nil, fmt.Errorf("unsupported scheme %s", certURL.Scheme)
	}
}

type certificateLoader func(context.Context) (*x509.Certificate, error)

func fromFile(path string) certificateLoader {
	return func(ctx context.Context) (*x509.Certificate, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("error opening certificate file: %v", err)
		}
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("error reading certificate file: %v", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("error decoding PEM data from file")
		}
		result, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing x509 certificate %v", err)
		}
		return result, nil
	}
}

func fromTLSHandshake(target *url.URL) certificateLoader {
	return func(ctx context.Context) (*x509.Certificate, error) {
		dialer := &net.Dialer{
			Deadline: time.Now().Add(time.Second * 10),
		}
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Deadline = deadline
		}
		cfg := &tls.Config{InsecureSkipVerify: true}
		conn, err := tls.DialWithDialer(dialer, target.Scheme, target.Host, cfg)
		if err != nil {
			return nil, fmt.Errorf("error dialing TLS connection %v", err)
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("error completing TLS handshake %v", err)
		}
		state := conn.ConnectionState()
		return state.PeerCertificates[0], nil
	}
}
