package venafi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

// These tests run real Terraform configurations through the terraform binary
// against the in-memory fake connector. Unlike the tests that call
// Resource.Diff and Resource.Apply directly, they exercise Terraform core: the
// gRPC protocol, plan/apply consistency checks, the empty plan expected after
// every apply, references between resources, lifecycle and timeouts blocks,
// and import.

// requireTerraformBinary skips the test when no terraform binary is available.
// The SDK would otherwise download the latest release.
func requireTerraformBinary(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC_TERRAFORM_PATH") != "" || os.Getenv("TF_ACC_TERRAFORM_VERSION") != "" {
		return
	}
	if _, err := exec.LookPath("terraform"); err != nil {
		t.Skip("terraform binary not found in PATH; set TF_ACC_TERRAFORM_PATH or install terraform to run this test")
	}
}

// fakeProviderFactories returns provider factories whose provider uses the
// given connector instead of connecting to a platform
func fakeProviderFactories(connector endpoint.Connector) map[string]func() (*schema.Provider, error) {
	return map[string]func() (*schema.Provider, error){
		"venafi": func() (*schema.Provider, error) {
			p := Provider()
			p.ConfigureContextFunc = func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
				return &ProviderConfig{VCertClient: connector}, nil
			}
			return p, nil
		},
	}
}

func checkFake(check func() error) resource.TestCheckFunc {
	return func(*terraform.State) error { return check() }
}

func awsSetupConfig(role string) string {
	return fmt.Sprintf(`
resource "venafi_cloud_provider" "aws" {
  name = "aws"
  type = "AWS"
  team = "Cloud Admins"
  aws {
    account_id = "123456789012"
    role       = %q
  }
}

resource "venafi_cloud_provider_validation" "aws" {
  cloud_provider_id = venafi_cloud_provider.aws.id
  lifecycle {
    replace_triggered_by = [venafi_cloud_provider.aws]
  }
}

resource "venafi_cloud_keystore" "acm" {
  name                         = "us-east-1"
  type                         = "ACM"
  cloud_provider_id            = venafi_cloud_provider_validation.aws.cloud_provider_id
  include_expired_certificates = false
  acm {
    region = "us-east-1"
  }
}
`, role)
}

func TestTerraformCloudProviderValidationAndKeystore(t *testing.T) {
	requireTerraformBinary(t)
	shortValidationRetries(t)

	connector := newFakeCloudConnector(endpoint.ConnectorTypeCloud)
	// the first validation fails, as when IAM changes have not propagated yet
	connector.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
		{Status: domain.CloudProviderStatusValidated},
	}

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: fakeProviderFactories(connector),
		Steps: []resource.TestStep{
			{
				// The keystore references the validation, so Terraform creates it
				// only once the provider is validated; the fake refuses keystores
				// on an unvalidated provider, as the platform does
				Config: awsSetupConfig("role-a"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("venafi_cloud_provider.aws", "aws.0.external_id"),
					resource.TestCheckResourceAttr("venafi_cloud_provider_validation.aws", "status", "VALIDATED"),
					resource.TestCheckResourceAttrPair("venafi_cloud_keystore.acm", "cloud_provider_id", "venafi_cloud_provider.aws", "id"),
					resource.TestCheckResourceAttr("venafi_cloud_keystore.acm", "include_expired_certificates", "false"),
					resource.TestCheckResourceAttr("venafi_cloud_keystore.acm", "cloud_provider_name", "provider"),
					checkFake(func() error {
						if connector.validateCalls != 2 {
							return fmt.Errorf("expected 2 validation attempts, got %d", connector.validateCalls)
						}
						return nil
					}),
				),
			},
			{
				// Changing the role resets the provider's status on the platform;
				// replace_triggered_by validates it again in the same apply, so the
				// plan after the apply is empty. The keystore is left alone.
				Config: awsSetupConfig("role-b"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("venafi_cloud_provider.aws", "aws.0.role", "role-b"),
					resource.TestCheckResourceAttr("venafi_cloud_provider_validation.aws", "status", "VALIDATED"),
					checkFake(func() error {
						if connector.validateCalls != 3 {
							return fmt.Errorf("expected the provider to be validated again, got %d validation calls", connector.validateCalls)
						}
						if connector.keystoresCreated != 1 {
							return fmt.Errorf("expected the keystore to be kept, got %d creations", connector.keystoresCreated)
						}
						return nil
					}),
				),
			},
			{
				ResourceName:            "venafi_cloud_provider.aws",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"team"},
			},
			{
				ResourceName:      "venafi_cloud_keystore.acm",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "venafi_cloud_provider_validation.aws",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestTerraformCloudProviderAzureAndGCP(t *testing.T) {
	requireTerraformBinary(t)
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: fakeProviderFactories(connector),
		Steps: []resource.TestStep{
			{
				// The Azure secret is never returned by the platform and the GCP
				// authorization method is defaulted by it; neither may cause a diff
				Config: `
resource "venafi_cloud_provider" "azure" {
  name = "azure"
  type = "AZURE"
  azure {
    application_id = "app"
    directory_id   = "dir"
    secret         = "s1"
  }
}

resource "venafi_cloud_provider" "gcp" {
  name = "gcp"
  type = "GCP"
  gcp {
    service_account_email = "sa@p.iam.gserviceaccount.com"
  }
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("venafi_cloud_provider.azure", "azure.0.secret", "s1"),
					resource.TestCheckResourceAttr("venafi_cloud_provider.gcp", "gcp.0.authorization_method", "VENAFI_GENERATED_KEY"),
					resource.TestMatchResourceAttr("venafi_cloud_provider.gcp", "gcp.0.public_key", regexp.MustCompile("^public-key-")),
				),
			},
			{
				ResourceName:            "venafi_cloud_provider.azure",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"azure.0.secret"},
			},
		},
	})
}

func TestTerraformCloudKeystoreDiscoverySchedule(t *testing.T) {
	requireTerraformBinary(t)
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)

	config := func(schedule string) string {
		scheduleLine := ""
		if schedule != "" {
			scheduleLine = fmt.Sprintf("discovery_schedule = %q", schedule)
		}
		return fmt.Sprintf(`
resource "venafi_cloud_keystore" "akv" {
  name              = "vault"
  type              = "AKV"
  cloud_provider_id = "p1"
  %s
  akv {
    key_vault_name = "prod-vault"
  }
}
`, scheduleLine)
	}

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: fakeProviderFactories(connector),
		Steps: []resource.TestStep{
			{
				Config: config("00 03 * * *"),
				Check:  resource.TestCheckResourceAttr("venafi_cloud_keystore.akv", "discovery_schedule", "00 03 * * *"),
			},
			{
				// removing the schedule from the configuration removes it
				Config: config(""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("venafi_cloud_keystore.akv", "discovery_schedule", ""),
					checkFake(func() error {
						u := connector.updatedKeystore
						if u == nil || u.Discovery == nil || u.Discovery.ScheduleSpecification == nil || *u.Discovery.ScheduleSpecification != "" {
							return fmt.Errorf("expected an update clearing the schedule, got %+v", u)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestTerraformCloudProviderValidationTimeout(t *testing.T) {
	requireTerraformBinary(t)
	interval := cloudProviderValidationRetryInterval
	cloudProviderValidationRetryInterval = 50 * time.Millisecond
	t.Cleanup(func() { cloudProviderValidationRetryInterval = interval })

	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
	}

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: fakeProviderFactories(connector),
		Steps: []resource.TestStep{
			{
				Config: `
resource "venafi_cloud_provider" "aws" {
  name = "aws"
  type = "AWS"
  aws {
    account_id = "123456789012"
    role       = "role"
  }
}

resource "venafi_cloud_provider_validation" "aws" {
  cloud_provider_id = venafi_cloud_provider.aws.id
  timeouts {
    create = "1s"
  }
}
`,
				ExpectError: regexp.MustCompile(`was not validated within 1s: role cannot be assumed`),
			},
		},
	})
}

func TestTerraformCloudProviderRejectsMismatchedBlock(t *testing.T) {
	requireTerraformBinary(t)
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: fakeProviderFactories(connector),
		Steps: []resource.TestStep{
			{
				Config: `
resource "venafi_cloud_provider" "azure" {
  name = "azure"
  type = "AZURE"
  aws {
    account_id = "123456789012"
    role       = "role"
  }
}
`,
				ExpectError: regexp.MustCompile(`requires a "azure" block`),
			},
		},
	})
}
