//go:build ngts
// +build ngts

package venafi

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5/pkg/policy"
)

// #nosec
var (
	ngtsEnvironmentVariables = fmt.Sprintf(`
variable "CLOUD_URL" {default = "%s"}
variable "CLIENT_ID" {default = "%s"}
variable "CLIENT_SECRET" {default = "%s"}
variable "TOKEN_URL" {default = "%s"}
variable "TSG_ID" {default = "%s"}
variable "CLOUD_ZONE" {default = "%s"}
variable "CLOUD_ZONE_RESTRICTED_2" {default = "%s"}
`,
		os.Getenv("CLOUD_URL"),
		os.Getenv("CLIENT_ID"),
		os.Getenv("CLIENT_SECRET"),
		os.Getenv("TOKEN_URL"),
		os.Getenv("TSG_ID"),
		os.Getenv("CLOUD_ZONE"),
		os.Getenv("CLOUD_ZONE_RESTRICTED_2"),
	)

	ngtsProv = ngtsEnvironmentVariables + `
provider "venafi" {
	url = "${var.CLOUD_URL}"
	client_id = "${var.CLIENT_ID}"
	client_secret = "${var.CLIENT_SECRET}"
	token_url = "${var.TOKEN_URL}"
	tsg_id = "${var.TSG_ID}"
	zone = "${var.CLOUD_ZONE}"
}
`

	ngtsPolicyResourceTest = `
%s
resource "venafi_policy" "ngts_policy" {
	provider = "venafi"
	zone="%s"
	policy_specification = file("%s")
}
output "policy_specification" {
	value = "${venafi_policy.ngts_policy.policy_specification}"
}`

	readPolicy = `
%s
resource "venafi_policy" "read_policy" {
	provider = "venafi"
	zone="%s"
    policy_specification = file("%s")
}`
)

func TestNGTSCreateEmptyPolicy(t *testing.T) {
	t.Parallel()
	data := testData{}
	data.zone = RandCitName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(ngtsPolicyResourceTest, ngtsProv, data.zone, data.filePath)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating Palo Alto Networks Next-Gen Trust Security (NGTS) empty zone: ", data.zone)
					return checkCreatePolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestNGTSCreatePolicy(t *testing.T) {
	t.Parallel()
	data := testData{}
	data.zone = RandCitName()

	data.filePath = GetAbsoluteFIlePath(policySpecNgts)

	config := fmt.Sprintf(ngtsPolicyResourceTest, ngtsProv, data.zone, data.filePath)
	t.Logf("Testing creating Palo Alto Networks Next-Gen Trust Security (NGTS) Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating Palo Alto Networks Next-Gen Trust Security (NGTS) zone: ", data.zone)
					return checkCreatePolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestNGTSImportPolicy(t *testing.T) {
	t.Parallel()
	config := getImportNgtsConfig()
	t.Logf("Testing importing Palo Alto Networks Next-Gen Trust Security (NGTS) Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_policy.read_policy",
				ImportStateId: os.Getenv("CLOUD_POLICY_SAMPLE"),
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Logf("Checking zone: %s's attributes", os.Getenv("CLOUD_POLICY_SAMPLE"))
					return checkImportNgtsPolicy(states)
				},
			},
		},
	})
}

func checkImportNgtsPolicy(states []*terraform.InstanceState) error {
	st := states[0]
	attributes := st.Attributes

	ps := attributes["policy_specification"]
	bytes := []byte(ps)

	var policySpecification policy.PolicySpecification
	err := json.Unmarshal(bytes, &policySpecification)
	if err != nil {
		return fmt.Errorf("policy specification is nil")
	}

	//get policy on directory.
	path := GetAbsoluteFIlePath(policySpecNgts)
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var filePolicySpecification policy.PolicySpecification
	err = json.Unmarshal(fileBytes, &filePolicySpecification)
	if err != nil {
		return err
	}

	equal := IsArrayStringEqual(filePolicySpecification.Policy.Domains, policySpecification.Policy.Domains)
	if !equal {
		return fmt.Errorf("domains are different, expected %+q but get %+q", filePolicySpecification.Policy.Domains, policySpecification.Policy.Domains)
	}

	//compare some attributes.
	equal = IsArrayStringEqual(filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)

	if !equal {
		return fmt.Errorf("key types are different, expected %+q but get %+q", filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)
	}

	equal = IsArrayStringEqual(filePolicySpecification.Policy.Subject.Countries, policySpecification.Policy.Subject.Countries)

	if !equal {
		return fmt.Errorf("countries are different, expected %+q but get %+q", filePolicySpecification.Policy.Subject.Countries, policySpecification.Policy.Subject.Countries)
	}

	if *(filePolicySpecification.Default.Subject.Locality) != *(policySpecification.Default.Subject.Locality) {
		return fmt.Errorf("default locality is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Locality), *(policySpecification.Default.Subject.Locality))
	}

	return nil
}

func getImportNgtsConfig() string {
	path := GetAbsoluteFIlePath(policySpecNgts)
	zone := os.Getenv("CLOUD_POLICY_SAMPLE")
	config := fmt.Sprintf(readPolicy, ngtsProv, zone, path)
	return config
}
