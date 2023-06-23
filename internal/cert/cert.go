package cert

import (
	"bytes"
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
	Tags                map[string]string
}

func (m Metrics) Output() string {
	epoch := m.EvaluatedAt.UnixMilli()
	var tags string
	if len(m.Tags) > 0 {
		buf := bytes.Buffer{}
		separator := ""
		for tag, value := range m.Tags {
			fmt.Fprintf(&buf, "%s%s=\"%s\"", separator, tag, value)
			if separator == "" {
				separator = ", "
			}
		}
		tags = fmt.Sprintf("{%s}", buf.String())
	}
	lines := []string{
		"# HELP cert_days_left number of days until certificate expires. Expired certificates produce negative numbers.",
		"# TYPE cert_days_left gauge",
		fmt.Sprintf("cert_days_left%s %f %d", tags, float64(m.SecondsUntilExpires)/secondsToDays, epoch),
		"# HELP cert_seconds_left number of seconds until certificate expires. Expired certificates produce negative numbers.",
		"# TYPE cert_seconds_left gauge",
		fmt.Sprintf("cert_seconds_left%s %d %d", tags, m.SecondsUntilExpires, epoch),
		"# HELP cert_issued_days total number of days since certificate was issued.",
		"# TYPE cert_issued_days counter",
		fmt.Sprintf("cert_issued_days%s %f %d", tags, float64(m.SecondsSinceIssued)/secondsToDays, epoch),
		"# HELP cert_issued_seconds total number of seconds since the certificate was issued.",
		"# TYPE cert_issued_seconds counter",
		fmt.Sprintf("cert_issued_seconds%s %d %d", tags, m.SecondsSinceIssued, epoch),
	}
	return strings.Join(lines, "\n")
}

// Config for evaluating metrics
type Config struct {
	// Now provider defaults to time.Now() when not provided
	Now        func() time.Time
	ServerName string
}

// CollectMetrics Loads a certificate at a particular location and
func CollectMetrics(ctx context.Context, path string, cfg Config) (Metrics, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var metrics Metrics
	certLoader, err := parse(path, cfg.ServerName)
	if err != nil {
		return metrics, fmt.Errorf("error parsing cert location: %v", err)
	}
	cert, err := certLoader(ctx)
	if err != nil {
		return metrics, err
	}
	fixStar := strings.Replace(cert.Subject.CommonName, "*", "STAR", 1)
	fixDot := strings.ReplaceAll(fixStar, ".", "_")
	metrics.Tags = map[string]string{"subject": fixDot}
	if cfg.ServerName != "" {
		if err := cert.VerifyHostname(cfg.ServerName); err != nil {
			return metrics, fmt.Errorf("error supplied servername not valid for this certificate: %v", err)
		}
		metrics.Tags["servername"] = cfg.ServerName
	}
	now := cfg.Now()
	metrics.EvaluatedAt = now
	metrics.SecondsSinceIssued = int(now.Sub(cert.NotBefore).Seconds())
	metrics.SecondsUntilExpires = int(cert.NotAfter.Sub(now).Seconds())
	return metrics, nil
}

func parse(cert, servername string) (certificateLoader, error) {
	if strings.HasPrefix(cert, "file://") {
		path := strings.TrimPrefix(cert, "file://")
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("cannot use directory: %s", path)
		}
		return fromFile(path), nil
	}

	// Parse as network URL
	certURL, err := url.Parse(cert)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate location as network url: %v", err)
	}
	switch certURL.Scheme {
	case "https":
		certURL.Scheme = "tcp"
		if certURL.Port() == "" {
			certURL.Host = fmt.Sprintf("%s:443", certURL.Host)
		}
		fallthrough
	case "tcp", "tcp4", "tcp6":
		return fromTLSHandshake(certURL, servername), nil
	default:
		return nil, fmt.Errorf("unsupported certificate location scheme \"%s\" for %s", certURL.Scheme, cert)
	}
}

type certificateLoader func(context.Context) (*x509.Certificate, error)

func fromFile(path string) certificateLoader {
	return func(ctx context.Context) (*x509.Certificate, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("error opening certificate file: %v", err)
		}
		defer f.Close()
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

func fromTLSHandshake(target *url.URL, servername string) certificateLoader {
	return func(ctx context.Context) (*x509.Certificate, error) {
		dialer := &net.Dialer{
			Deadline: time.Now().Add(time.Second * 10),
		}
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Deadline = deadline
		}
		cfg := &tls.Config{InsecureSkipVerify: true}
		if servername != "" {
			cfg.ServerName = servername
		}
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
