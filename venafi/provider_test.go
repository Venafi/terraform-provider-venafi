package venafi

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"regexp"
	"testing"
)

var testAccProvider *schema.Provider

var testAccProviderFactories map[string]func() (*schema.Provider, error)

func init() {
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"venafi": func() (*schema.Provider, error) {
			return Provider(), nil
		},
	}
}

func TestProvider(t *testing.T) {
	provider := Provider()
	if err := provider.InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ = *Provider()
}

func TestNormalizedZones(t *testing.T) {
	zones := []string{
		"Open Source\\vcert",
		"Open Source Integrations\\\\Unrestricted",
		"Open Source Integrations\\Unrestricted",
		"Certificates\\Automation\\Terraform",
		"Certificates\\\\Automation\\\\Terraform",
		"\\VED\\Policy\\One\\Two\\Three",
		"\\\\VED\\\\Policy\\\\One\\\\Two\\\\Three",
	}
	var re, _ = regexp.Compile("^(\\\\VED|[\\w\\-]+)(\\s?[\\w\\-]+)*(\\\\[\\w\\-]+(\\s?[\\w\\-]+)*)*$")

	for _, zone := range zones {
		newZone := normalizeZone(zone)

		if !re.MatchString(newZone) {
			t.Fatal(fmt.Printf("Zone %s is not normalized", newZone))
		}
	}
}
func testAccPreCheck(t *testing.T) {
	// We will use this function later on to make sure our test environment is valid.
	// For example, you can make sure here that some environment variables are set.
}
