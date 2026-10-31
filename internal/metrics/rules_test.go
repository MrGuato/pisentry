package metrics

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	plainRules = "../../deploy/prometheus/pisentry-rules.yaml"
	crdRules   = "../../deploy/kubernetes/apps/base/pisentry/prometheusrule.yaml"
)

// An alert on a metric that was renamed never fires and never errors. Every
// pisentry_* name in the shipped rules must exist in the registry.
func TestAlertRulesReferenceRealMetrics(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSet().Reg.Write(&buf); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) `).FindAllStringSubmatch(buf.String(), -1) {
		known[m[1]] = true
	}
	for _, path := range []string{plainRules, crdRules} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range regexp.MustCompile(`\bpisentry_[a-z_]+\b`).FindAllString(string(b), -1) {
			if name == "pisentry_rules" || strings.HasSuffix(name, "_") {
				continue // file names and prose, not metrics
			}
			if !known[name] {
				t.Errorf("%s: unknown metric %s", path, name)
			}
		}
	}
}

// The PrometheusRule carries the plain rule groups verbatim, indented under
// spec, followed by Kubernetes-only groups.
func TestPrometheusRuleMatchesPlainRules(t *testing.T) {
	plain, err := os.ReadFile(plainRules)
	if err != nil {
		t.Fatal(err)
	}
	crd, err := os.ReadFile(crdRules)
	if err != nil {
		t.Fatal(err)
	}
	groups := string(plain[bytes.Index(plain, []byte("groups:\n")):])
	_, spec, ok := strings.Cut(string(crd), "\nspec:\n")
	if !ok {
		t.Fatal("no spec in PrometheusRule")
	}
	var dedent strings.Builder
	for _, l := range strings.SplitAfter(spec, "\n") {
		dedent.WriteString(strings.TrimPrefix(l, "  "))
	}
	if !strings.HasPrefix(dedent.String(), groups) {
		t.Fatalf("%s spec.groups does not start with the groups of %s; copy them over (indent by two spaces)", crdRules, plainRules)
	}
}
