//go:build vaas
// +build vaas

package venafi

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5/pkg/policy"
)

// #nosec
var (
	envVariables = fmt.Sprintf(`
variable "CLOUD_URL" {default = "%s"}
variable "CLOUD_APIKEY" {default = "%s"}
variable "CLOUD_ZONE" {default = "%s"}
`,
		os.Getenv("CLOUD_URL"),
		os.Getenv("CLOUD_APIKEY"),
		os.Getenv("CLOUD_ZONE"))

	vaasProv = envVariables + `
provider "venafi" {
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
}
`

	vaasPolicyResourceTest = `
%s
resource "venafi_policy" "vaas_policy" {
	provider = "venafi"
	zone="%s"
	policy_specification = file("%s")
}
output "policy_specification" {
	value = "${venafi_policy.vaas_policy.policy_specification}"
}`

	readPolicy = `
%s
resource "venafi_policy" "read_policy" {
	provider = "venafi"
	zone="%s"
    policy_specification = file("%s")
}`
)

func TestVAASCreateEmptyPolicy(t *testing.T) {
	t.Parallel()
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(vaasPolicyResourceTest, vaasProv, data.zone, data.filePath)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating CyberArk Certificate Manager, SaaS empty zone: ", data.zone)
					return checkCreatePolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestVAASCreatePolicy(t *testing.T) {
	t.Parallel()
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(policySpecVaas)

	config := fmt.Sprintf(vaasPolicyResourceTest, vaasProv, data.zone, data.filePath)
	t.Logf("Testing creating CyberArk Certificate Manager, SaaS Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating CyberArk Certificate Manager, SaaS zone: ", data.zone)
					return checkCreatePolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestVAASImportPolicy(t *testing.T) {
	t.Parallel()
	config := getImportVaasConfig()
	t.Logf("Testing importing CyberArk Certificate Manager, SaaS Zone:\n %s", config)
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
					return checkImportVaasPolicy(states)
				},
			},
		},
	})
}

func checkImportVaasPolicy(states []*terraform.InstanceState) error {
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
	path := GetAbsoluteFIlePath(policySpecVaas)
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

	if *(filePolicySpecification.Policy.MaxValidDays) != *(policySpecification.Policy.MaxValidDays) {
		return fmt.Errorf("max valid period is different, expected %s but get %s", strconv.Itoa(*(filePolicySpecification.Policy.MaxValidDays)), strconv.Itoa(*(policySpecification.Policy.MaxValidDays)))
	}

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

func getImportVaasConfig() string {
	path := GetAbsoluteFIlePath(policySpecVaas)
	zone := os.Getenv("CLOUD_POLICY_SAMPLE")
	zone = strings.Replace(zone, "\\", "\\\\", 1)
	config := fmt.Sprintf(readPolicy, vaasProv, zone, path)
	return config
}
