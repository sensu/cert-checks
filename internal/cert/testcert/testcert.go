package testcert

import "time"

// TestCert PEM encoded TLS cert for imposter.sensu.io
// Generated using go's crypto/tls/generate_cert.go
// go run generate_cert.go --host imposter.sensu.io --ca --start-date "Jan 1 00:00:00 1970" --duration 72h
var TestCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIQRMuY4PUxXi94si6YcOz23DANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTcwMDEwMTAwMDAwMFoXDTcwMDEwNDAwMDAw
MFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK2SJHykea+3iZjcEJzmjL42y/AS4xliVCfxK61jHC/xZOmemiFPHAFW
GiVYn0LKl8KvmJyg3JTuroOnQdK0NMHtmoyCUv05Sp3ddELdZgFVr0odrhN9/0uW
Pfp1jj5NqoYS/04vK7nh9fzjYOMpIxkE7r+csJfkOK0PQsdYlvfOMppySFVNmn1b
sHVHX2zlm7/SmIOQxJ4DWzJ+gzUWYp8BK7exqhiHzf3rqDSJOG3Q9R7jqNnc9yUB
e6tqXHNqC9B4fbnVKYp2g8FdRiJmCp9Hi8ysmO0UFv1hL2of70OXuFoYjsakWJhJ
yxHZjBGA27TFRVy6YD+dM1LNHPbegA0CAwEAAaN1MHMwDgYDVR0PAQH/BAQDAgKk
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
FK17S8zBFO8x8mzGwYYm1gogxLgGMBwGA1UdEQQVMBOCEWltcG9zdGVyLnNlbnN1
LmlvMA0GCSqGSIb3DQEBCwUAA4IBAQBQ9U+rdvD5pWl+grVhomqyiWtu6WqC81Kz
FTCIaw/XwBg5zS3rwvhZZNtsS75uK/7MTRUEwShbg4ShSYAnmDdsnHK/NjQneFkd
FwZ6cFUL9+lu0gyfjXcmXPHzJNiDJduG9njDKks5SUNrhwAuWkKfkg9x2rYVZ1yo
6Cim02RYIKU8VWuj68Fbn8/uKiHG3y+0XmO/x6Ixfopxrcp12Kb44bJn+brsceuz
B1chiuizWWEP0N130b3i9rE+J9A5/rrGmHBvmr3gXLSPn3q06brYYcVpP7jGwQsr
DjyfPCb7GQ1zaqBaVqFlEYbkEO7j6IkS4/CpKP0noIDEh8XGtTWK
-----END CERTIFICATE-----`)

// TestKey is the corresponding private key to TestCert
var TestKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCtkiR8pHmvt4mY
3BCc5oy+NsvwEuMZYlQn8SutYxwv8WTpnpohTxwBVholWJ9CypfCr5icoNyU7q6D
p0HStDTB7ZqMglL9OUqd3XRC3WYBVa9KHa4Tff9Llj36dY4+TaqGEv9OLyu54fX8
42DjKSMZBO6/nLCX5DitD0LHWJb3zjKackhVTZp9W7B1R19s5Zu/0piDkMSeA1sy
foM1FmKfASu3saoYh83966g0iTht0PUe46jZ3PclAXuralxzagvQeH251SmKdoPB
XUYiZgqfR4vMrJjtFBb9YS9qH+9Dl7haGI7GpFiYScsR2YwRgNu0xUVcumA/nTNS
zRz23oANAgMBAAECggEAPa/+/72E8gqNAKLV1K2rv77B5GUSCWeE+V0hZNIgpnlo
oA8aQFRZY7AyQquojphqL2sxFhmly9i4dVnwbu5VAcdschuvWwgNmOWn+EuvgTHu
xqydvZe+MCMJjAZTs5juzg/aZPMm2z2Pq300ZgeszauPHtKVgKY/7mHKHgdCQHeW
KvvUrgtazWHYfnfOUnUZ5BEMXh44ypXWWU1uoMfSgYc0ZWAz3ahSKgjfsrpPR89P
SF94pJavvCEEVcyAvlpnTem5TINtbu3Dw1BwbjEmqAWimZGen5vMcPau1i0noT28
7mkPpzHBYen9L+HDbotRRJuIuVtcCJtvAeuYehoBEQKBgQDF99VS7OdFgnKPU66Z
F6Q0hwSEBS1rHNVsJdPvjDQgaSmf7Fmner0B+Q694b/n3S3FVfEebpwoMp8iVnzc
Kw/ObVaXzyHWN868uz2Xl7Z51AGO+UXHlGh93xWctFpl0HGI8izIJlMXwwhU1tKU
S79khMkHbH3SHApYsbpGq0SPCwKBgQDgc3ZRfa1/7KjKQXeS06g68A6R4xSI7rUz
EhOExpOHFiAb20vGUmR+4YbcCiLvNNAgnvnT1mZZiHe1zNnoy/HlXl9/8M2up0AJ
qS64XFSu+/AZDyVPVSBoqX5abV0agNnL6inJLF6zJFpmKc4WJd+273teubiEbGIa
RgpTZaT8RwKBgHspCCojAG6aDTNl2EWeE6YqKYEIx4zPz2cM0aFCFFvlkOPRYqVz
EotbqvQusflJ/OO759oK7lODysTOEbfXgmnmU+z2DBL9fTylMFhTJk78ukt8gRD9
H1TPqN5oxaR53WhZYcrTLPane1Nsom1oApZCld5sfIpur3EmgMDeZDSpAoGALX3Z
dkzVtH7f+xZnyN+TUlbDbTgsOlC/cxlv0VJ6JkAKw/qfkhOzALBvJ/v59qeqo2H1
WsUyu2TYdoWNiQyE+6s0CfdhiMunRA4BRSaZl1nC4SFbu4eSaQQpcuSFoVCKVDUi
wP54NzDgDaLdfUmx3R8OzzUvO8/H1nFpuFt6pBMCgYB74kHCuc9RokDfk39nhKo5
8S7dfV/9MMVVzj0oxCs6HgxpUAcj8GubYZPHSbaVk+KnCu9D4Z2JOVQbO1RSVIZM
TitQUfyDJguoP5N2OlkmUCsFwYnc5tIUgaE8U3Gyqyjvt9NPPpxPwTjSIYT1zieK
4Xku6HNopl/EpBCDxks0ow==
-----END PRIVATE KEY-----`)

// TimeEffective how long the certificate is effective
var TimeEffective = time.Duration(time.Hour * 72)

// NotBefore certificate issued at beginning of epoch
var NotBefore = time.Unix(0, 0)

// NotAfter certificate valid until 1970-01-04 00:00:00 +0000 UTC
var NotAfter = time.Unix(0, 0).Add(TimeEffective)