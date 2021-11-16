package testcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// SigningKey PKCS8 ed25519 private key
var SigningKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFas9kzil+15Ywf4USE6HTQIFROAEpZX4BgWzR9KSLbo
-----END PRIVATE KEY-----
`)

func New(host string, notBefore time.Time, duration time.Duration) (tls.Certificate, []byte, error) {
	var tlsCert tls.Certificate
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tlsCert, nil, err
	}

	temp := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization:       []string{"Sumo Logic Inc"},
			OrganizationalUnit: []string{"Sensu Test"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(duration),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{host},
		IsCA:     true,
	}

	pkBlock, _ := pem.Decode(SigningKey)
	tmpKey, err := x509.ParsePKCS8PrivateKey(pkBlock.Bytes)
	if err != nil {
		return tlsCert, nil, err
	}
	priv := tmpKey.(ed25519.PrivateKey)

	b, err := x509.CreateCertificate(rand.Reader, &temp, &temp, priv.Public(), priv)
	if err != nil {
		return tlsCert, nil, err
	}
	var cert bytes.Buffer
	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
		return tlsCert, nil, err
	}
	tlsCert, err = tls.X509KeyPair(cert.Bytes(), SigningKey)
	return tlsCert, cert.Bytes(), err
}
