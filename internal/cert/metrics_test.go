package cert_test

import (
	"testing"
	"time"

	"github.com/sensu/cert-checks/internal/cert"
)

func TestMetricsOutput(t *testing.T) {
	m := cert.Metrics{
		EvaluatedAt:         time.Unix(42, 0),
		SecondsSinceIssued:  100,
		SecondsUntilExpires: 2000,
	}
	actual := m.Output()

	expected := `# TYPE cert_days_left gauge
cert_days_left 0.023148 42000
# TYPE cert_seconds_left gauge
cert_seconds_left 2000 42000
# TYPE cert_issued_days counter
cert_issued_days 0.001157 42000
# TYPE cert_issued_seconds counter
cert_issued_seconds 100 42000`
	if actual != expected {
		t.Errorf("Unexpected output. Wanted:\n%s\n Got:\n%s", expected, actual)
	}
}

func TestMetricsOutputServerName(t *testing.T) {
	m := cert.Metrics{
		EvaluatedAt:         time.Unix(42, 0),
		SecondsSinceIssued:  100,
		SecondsUntilExpires: 2000,
		Tags:                map[string]string{"servername": "sensu.io"},
	}
	actual := m.Output()

	expected := `# TYPE cert_days_left gauge
cert_days_left{servername="sensu.io"} 0.023148 42000
# TYPE cert_seconds_left gauge
cert_seconds_left{servername="sensu.io"} 2000 42000
# TYPE cert_issued_days counter
cert_issued_days{servername="sensu.io"} 0.001157 42000
# TYPE cert_issued_seconds counter
cert_issued_seconds{servername="sensu.io"} 100 42000`
	if actual != expected {
		t.Errorf("Unexpected output. Wanted:\n%s\n Got:\n%s", expected, actual)
	}
}
