package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterIncAndWrite(t *testing.T) {
	r := NewRegistry()
	r.RequestsTotal.Inc("allow")
	r.RequestsTotal.Inc("allow")
	r.RequestsTotal.Inc("reject")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `sentinel_requests_total{decision="allow"} 2`) {
		t.Errorf("expected allow=2 in output, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_requests_total{decision="reject"} 1`) {
		t.Errorf("expected reject=1 in output, got:\n%s", body)
	}
}

func TestGaugeSetAndAdd(t *testing.T) {
	g := newGauge("test_gauge", "a test gauge")
	g.Set(5)
	g.Add(3)
	g.Add(-1)
	if got := g.v.Load(); got != 7 {
		t.Errorf("expected 7, got %d", got)
	}
}

func TestHistogramObserve(t *testing.T) {
	h := newHistogram("test_hist", "a test histogram")
	h.Observe(0.00003) // falls in smallest bucket
	h.Observe(0.2)      // falls in a later bucket
	h.Observe(2.0)      // falls only in +Inf

	var b strings.Builder
	h.write(&b)
	out := b.String()

	if !strings.Contains(out, `test_hist_count 3`) {
		t.Errorf("expected count 3, got:\n%s", out)
	}
	if !strings.Contains(out, `le="+Inf"} 3`) {
		t.Errorf("expected +Inf bucket to be 3, got:\n%s", out)
	}
	if !strings.Contains(out, `le="0.00005"} 1`) {
		t.Errorf("expected smallest bucket to be 1, got:\n%s", out)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	r := NewRegistry()
	req := httptest.NewRequest("POST", "/metrics", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
