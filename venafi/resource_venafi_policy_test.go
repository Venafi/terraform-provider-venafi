package venafi

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"os"
	"testing"
)

var (
	envVariables = fmt.Sprintf(`
variable "TPP_USER" {default = "%s"}
variable "TPP_PASSWORD" {default = "%s"}
variable "TPP_URL" {default = "%s"}
variable "TPP_ZONE" {default = "%s"}
variable "TPP_ZONE_ECDSA" {default = "%s"}
variable "TRUST_BUNDLE" {default = "%s"}
variable "CLOUD_URL" {default = "%s"}
variable "CLOUD_APIKEY" {default = "%s"}
variable "CLOUD_ZONE" {default = "%s"}
variable "TPP_ACCESS_TOKEN" {default = "%s"}
`,
		os.Getenv("TPP_USER"),
		os.Getenv("TPP_PASSWORD"),
		os.Getenv("TPP_URL"),
		os.Getenv("TPP_ZONE"),
		os.Getenv("TPP_ZONE_ECDSA"),
		os.Getenv("TRUST_BUNDLE"),
		os.Getenv("CLOUD_URL"),
		os.Getenv("CLOUD_APIKEY"),
		os.Getenv("CLOUD_ZONE"),
		os.Getenv("TPP_ACCESS_TOKEN"))

	tokenProv = environmentVariables + `
provider "venafi" {
	alias = "token_tpp"
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`

	cloudProv = environmentVariables + `
provider "venafi" {
	alias = "cloud"
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone = "${var.CLOUD_ZONE}"
}
`

	emptyPolicyTest = `
%s
resource "venafi_policy" "empty_policy" {
	provider = "venafi.cloud"
	zone="%s"
	policy_specification_path = "%s"
}
output "policy_specification" {
	value = "${venafi_policy.empty_policy.policy_specification}"
}`

	readPolicy = `
%s
resource "venafi_policy" "read_policy" {
	provider = "venafi.cloud"
	zone="%s"
	policy_specification_path = "%s"
}`
)

func TestCreateEmptyPolicy(t *testing.T) {
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()
	root_dir := GetRootDir()
	data.file_path = root_dir + empty_policy
	config := fmt.Sprintf(emptyPolicyTest, cloudProv, data.zone, data.file_path)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating empty zone: ", data.zone)
					return checkCreateEmptyPolicy(t, &data, s)
				},
			},
		},
	})
}

func checkCreateEmptyPolicy(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Validate Creating empty policy", data.zone)

	pstUntyped := s.RootModule().Outputs["policy_specification"].Value

	ps, ok := pstUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"policy_specification\" is not a string")
	}

	bytes := []byte(ps)

	var policySpecification policy.PolicySpecification
	err := json.Unmarshal(bytes, &policySpecification)
	if err != nil {
		return fmt.Errorf("policy specification is nil")
	}

	return nil
}

/*
func TestRadPolicy(t *testing.T) {
	root_dir := GetRootDir()
	file_path := root_dir + "/test_files/empty_policy.json"
	config := fmt.Sprintf(readPolicy, cloudProvider, "vcert_cloud\\\\terraform-test", file_path)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config:        getConfig(),
				ResourceName:  "venafi_policy.read_policy",
				ImportStateId: "vcert-amoo-0004\\terraform-test-010",
				ImportState:   true,
				ImportStateVerify: true,
				Check: func(s *terraform.State) error {
					t.Log("Creating empty zone: ")
					return checkReadEmptyPolicy(t, s)
				},
			},
		},
	})
}


func checkReadEmptyPolicy(t *testing.T, s *terraform.State) error {

	return nil
}

func getConfig() string {
	root_dir := GetRootDir()
	file_path := root_dir + "/test_files/empty_policy.json"
	config := fmt.Sprintf(readPolicy, cloudProvider, "vcert_cloud\\\\terraform-test", file_path)
	return config
}
*/
