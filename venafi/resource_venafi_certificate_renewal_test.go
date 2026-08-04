package venafi

// Regression tests for automatic renewal driven by expiration_window.
//
// These run entirely offline against the dev_mode fake CA, so they belong to the
// standard (untagged) unit suite exercised by `make test_go`. The fake CA issues
// certificates valid for ~90 days, so an expiration_window above the remaining
// validity (renewAlwaysWindow) puts the certificate inside its renewal window on
// every apply, and a small one (renewNeverWindow) keeps it outside.
//
// They guard the defect where a certificate inside expiration_window was not
// renewed: renewal used to hinge on renew_required, a user-settable attribute, so
// any configuration that supplied it (directly, or by excluding it with
// ignore_changes) collapsed the diff and Terraform reported "No changes".

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	// renewAlwaysWindow is larger than the fake CA's remaining validity, so the
	// certificate is always inside its renewal window.
	renewAlwaysWindow = 3000
	// renewNeverWindow is far smaller than the remaining validity, so the
	// certificate is never inside its renewal window.
	renewNeverWindow = 168
)

// devRenewConfig builds a dev_mode venafi_certificate configuration. extra is
// injected inside the resource block (for renew_required or a lifecycle block).
func devRenewConfig(cn string, expirationWindow int, extra string) string {
	return fmt.Sprintf(`
provider "venafi" {
	alias    = "dev"
	dev_mode = true
}
resource "venafi_certificate" "dev_certificate" {
	provider          = "venafi.dev"
	common_name       = "%s"
	%s
	expiration_window = %d
	%s
}
output "certificate" {
	value = venafi_certificate.dev_certificate.certificate
}
output "private_key" {
	value     = venafi_certificate.dev_certificate.private_key_pem
	sensitive = true
}`, cn, rsa2048, expirationWindow, extra)
}

// assertRenewsAcrossApply runs two applies of the same renewal configuration and
// asserts the certificate is re-enrolled (serial changes) each time. The plan is
// intentionally non-empty because the certificate is permanently inside its
// renewal window; that is expected only in these tests, where expiration_window is
// deliberately oversized.
func assertRenewsAcrossApply(t *testing.T, extra string) {
	t.Helper()
	data := testData{}
	data.cn = randSeq(9) + ".venafi.example.com"
	config := devRenewConfig(data.cn, renewAlwaysWindow, extra)
	t.Logf("Testing renewal with config:\n %s", config)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					previousSerial := data.serial
					if err := checkStandardCert(t, &data, s); err != nil {
						return err
					}
					if data.serial == previousSerial {
						return fmt.Errorf("certificate was not renewed: serial %s is unchanged after re-apply", data.serial)
					}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestDevRenewPlainConfig is the baseline: a plain configuration inside the
// expiration window renews.
func TestDevRenewPlainConfig(t *testing.T) {
	assertRenewsAcrossApply(t, "")
}

// TestDevRenewWithRenewRequiredInConfig covers the reported defect: renew_required
// set in the configuration must not suppress renewal.
func TestDevRenewWithRenewRequiredInConfig(t *testing.T) {
	assertRenewsAcrossApply(t, "renew_required = true")
}

// TestDevRenewWithIgnoreChanges covers the other trigger: excluding renew_required
// via ignore_changes must not suppress renewal.
func TestDevRenewWithIgnoreChanges(t *testing.T) {
	assertRenewsAcrossApply(t, "lifecycle {\n\t\tignore_changes = [renew_required]\n\t}")
}

// TestDevNoRenewOutsideWindow asserts a certificate comfortably outside its
// expiration window produces an empty plan even when renew_required is pinned true
// in the configuration. Without ExpectNonEmptyPlan, the test framework fails on any
// residual diff, so this guards against per-apply churn.
func TestDevNoRenewOutsideWindow(t *testing.T) {
	data := testData{}
	data.cn = randSeq(9) + ".venafi.example.com"
	config := devRenewConfig(data.cn, renewNeverWindow, "renew_required = true")
	t.Logf("Testing steady state with config:\n %s", config)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					return checkStandardCert(t, &data, s)
				},
			},
		},
	})
}
