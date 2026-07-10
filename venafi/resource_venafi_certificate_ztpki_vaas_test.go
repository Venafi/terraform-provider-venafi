//go:build vaas
// +build vaas

package venafi

// VC-55689 — live end-to-end tests for the ZTPKI (third-party CA) connector on CM SaaS.
//
// Bug: when enrolling against a ZTPKI issuing template with a *user-provided* (local) CSR,
// the requested validity period (valid_days) is ignored and the certificate is issued with
// the issuing-template default. Service-generated CSR and the built-in CA are unaffected.
//
// These tests assert the CORRECT behavior (issued validity == requested valid_days). They are
// therefore expected to FAIL against a vulnerable stack (reproducing the bug) and PASS once the
// fix lands in VCert.
//
// Required environment (tests skip if CLOUD_ZONE_ZTPKI is unset):
//   CLOUD_URL          e.g. https://api.venafi.cloud
//   CLOUD_APIKEY       CM SaaS API key for the tenant hosting the ZTPKI template
//   CLOUD_ZONE_ZTPKI   ZTPKI zone as "application\\issuing-template-alias"
//   ZTPKI_VALID_DAYS   optional; requested validity in days (default 30).
//                      Pick a value that differs from the template default so the bug is visible.
//
// Run:
//   TF_ACC=1 go test -tags=vaas -run '^TestVAASZTPKIValidity' ./venafi -v -timeout 30m

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const ztpkiValidDaysDefault = 30

var (
	ztpkiEnvVariables = fmt.Sprintf(`
variable "CLOUD_URL" {default = "%s"}
variable "CLOUD_APIKEY" {default = "%s"}
variable "CLOUD_ZONE_ZTPKI" {default = "%s"}
`,
		os.Getenv("CLOUD_URL"),
		os.Getenv("CLOUD_APIKEY"),
		os.Getenv("CLOUD_ZONE_ZTPKI"),
	)

	ztpkiProvider = ztpkiEnvVariables + `
provider "venafi" {
	alias   = "ztpki"
	url     = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone    = "${var.CLOUD_ZONE_ZTPKI}"
}
`

	// Local (user-provided) CSR — the failing case in VC-55689. csr_origin defaults to "local".
	ztpkiConfigLocalCSR = `
%s
resource "venafi_certificate" "ztpki" {
	provider          = "venafi.ztpki"
	common_name       = "%s"
	%s
	key_password      = "%s"
	valid_days        = %d
	expiration_window = %d
}
output "certificate" {
	value = "${venafi_certificate.ztpki.certificate}"
}`

	// Service-generated CSR — the working control case in VC-55689.
	ztpkiConfigServiceCSR = `
%s
resource "venafi_certificate" "ztpki" {
	provider          = "venafi.ztpki"
	common_name       = "%s"
	%s
	key_password      = "%s"
	valid_days        = %d
	expiration_window = %d
	csr_origin        = "service"
}
output "certificate" {
	value = "${venafi_certificate.ztpki.certificate}"
}`
)

// ztpkiValidDays returns the requested validity in days (ZTPKI_VALID_DAYS or the default).
func ztpkiValidDays(t *testing.T) int {
	raw := os.Getenv("ZTPKI_VALID_DAYS")
	if raw == "" {
		return ztpkiValidDaysDefault
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		t.Fatalf("invalid ZTPKI_VALID_DAYS %q: must be a positive integer", raw)
	}
	return v
}

// skipUnlessZtpki skips the test unless a ZTPKI zone is configured in the environment.
func skipUnlessZtpki(t *testing.T) {
	if os.Getenv("CLOUD_ZONE_ZTPKI") == "" {
		t.Skip("CLOUD_ZONE_ZTPKI not set; skipping ZTPKI live e2e test (see VC-55689)")
	}
}

// checkZtpkiCertValidity asserts the issued certificate's validity window (NotAfter-NotBefore)
// matches the requested number of days within tolerance. Measuring the *duration* directly is
// what exposes VC-55689: the bug substitutes the template default for the requested period.
func checkZtpkiCertValidity(t *testing.T, expectedDays int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		out, ok := s.RootModule().Outputs["certificate"]
		if !ok || out.Value == nil {
			return fmt.Errorf("no \"certificate\" output found in state")
		}
		certStr, ok := out.Value.(string)
		if !ok || certStr == "" {
			return fmt.Errorf("\"certificate\" output is empty or not a string")
		}
		block, _ := pem.Decode([]byte(certStr))
		if block == nil {
			return fmt.Errorf("could not decode certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing certificate: %w", err)
		}

		actualDays := int(math.Round(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24))
		// Allow ±1 day for issuance backdating / rounding.
		const tolDays = 1
		diff := actualDays - expectedDays
		if diff < 0 {
			diff = -diff
		}
		t.Logf("ZTPKI cert validity: requested=%d days, issued=%d days (NotBefore=%s, NotAfter=%s)",
			expectedDays, actualDays, cert.NotBefore, cert.NotAfter)
		if diff > tolDays {
			return fmt.Errorf(
				"VC-55689: requested valid_days=%d but ZTPKI issued a %d-day certificate "+
					"(NotBefore=%s NotAfter=%s) — validity period was NOT honored",
				expectedDays, actualDays, cert.NotBefore, cert.NotAfter)
		}
		return nil
	}
}

// TestVAASZTPKIValidityLocalCSR reproduces VC-55689: local CSR + valid_days against ZTPKI.
// Expected to FAIL on a vulnerable stack (validity ignored) and PASS after the VCert fix.
func TestVAASZTPKIValidityLocalCSR(t *testing.T) {
	skipUnlessZtpki(t)
	t.Parallel()

	validDays := ztpkiValidDays(t)
	cn := randSeq(9) + ".venafi.example.com"
	keyPassword := "123xxx"
	expirationWindow := 48

	config := fmt.Sprintf(ztpkiConfigLocalCSR, ztpkiProvider, cn, rsa2048, keyPassword, validDays, expirationWindow)
	t.Logf("Testing ZTPKI local-CSR validity with config:\n%s", config)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  checkZtpkiCertValidity(t, validDays),
			},
		},
	})
}

// TestVAASZTPKIValidityServiceCSR is the control from VC-55689: service-generated CSR + valid_days
// against ZTPKI. Expected to PASS both before and after the fix.
func TestVAASZTPKIValidityServiceCSR(t *testing.T) {
	skipUnlessZtpki(t)
	t.Parallel()

	validDays := ztpkiValidDays(t)
	cn := randSeq(9) + ".venafi.example.com"
	keyPassword := "123xxx"
	expirationWindow := 48

	config := fmt.Sprintf(ztpkiConfigServiceCSR, ztpkiProvider, cn, rsa2048, keyPassword, validDays, expirationWindow)
	t.Logf("Testing ZTPKI service-CSR validity with config:\n%s", config)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  checkZtpkiCertValidity(t, validDays),
			},
		},
	})
}
