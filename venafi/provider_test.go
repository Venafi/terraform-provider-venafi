package venafi

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const certPassword = "test123"

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

	var re, _ = regexp.Compile("^(\\\\VED|[\\w\\-]+)(\\s?[\\w\\-]+)*(\\\\[\\w\\-]+(\\s?[\\w\\-]+)*)*$") //nolint

	for _, zone := range zones {
		newZone := normalizeZone(zone)

		if !re.MatchString(newZone) {
			t.Fatal(fmt.Printf("Zone %s is not normalized", newZone))
		}
	}
}

func TestSetTLSConfig(t *testing.T) {
	certs := []string{"cert.p12", "cert-legacy.p12"}
	for _, v := range certs {
		loc := GetAbsoluteFIlePath(fmt.Sprintf("/test_files/%s", v))
		ctx := context.Background()
		cert, err := os.ReadFile(loc)
		if err != nil {
			t.Fatalf("Failed to read file: %s - %s", loc, err)
		}
		err = setTLSConfig(ctx, cert, certPassword)
		if err != nil {
			t.Fatalf("Failed set TLS Config: %s", err)
		}
	}
}
