package venafi

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"io/ioutil"
	"os"
	"strconv"
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

	cloudPolicyResourceTest = `
%s
resource "venafi_policy" "cloud_policy" {
	provider = "venafi.cloud"
	zone="%s"
	policy_specification_path = "%s"
}
output "policy_specification" {
	value = "${venafi_policy.cloud_policy.policy_specification}"
}`

	tppPolicyResourceTest = `
%s
resource "venafi_policy" "tpp_policy" {
	provider = "venafi.token_tpp"
	zone="%s"
	policy_specification_path = "%s"
}
output "policy_specification" {
	value = "${venafi_policy.tpp_policy.policy_specification}"
}`

	readPolicy = `
%s
resource "venafi_policy" "read_policy" {
	provider = "venafi.cloud"
	zone="%s"
	policy_specification_path = "%s"
}`
)

//-----------------------------------------------cloud test cases begins----------------------------------------------//

func TestCreateCloudEmptyPolicy(t *testing.T) {
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(cloudPolicyResourceTest, cloudProv, data.zone, data.filePath)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating VaaS empty zone: ", data.zone)
					return checkCreateCloudPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestCreateCloudPolicy(t *testing.T) {
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(policySpecCloud)

	config := fmt.Sprintf(cloudPolicyResourceTest, cloudProv, data.zone, data.filePath)
	t.Logf("Testing creating VaaS Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating VaaS zone: ", data.zone)
					return checkCreateCloudPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func checkCreateCloudPolicy(t *testing.T, data *testData, s *terraform.State, validateAttr bool) error {
	t.Log("Validate Creating VaaS empty policy", data.zone)

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

	if !validateAttr {
		return nil
	}

	//get policy on directory.
	file, err := os.Open(data.filePath)
	if err != nil {
		return err
	}

	fileBytes, err := ioutil.ReadAll(file)
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

	if *(filePolicySpecification.Default.Subject.Locality) != *(policySpecification.Default.Subject.Locality) {
		return fmt.Errorf("default locality is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Locality), *(policySpecification.Default.Subject.Locality))
	}

	return nil
}

//------------------------------------------------cloud test cases ends-----------------------------------------------//

//------------------------------------------------TPP test cases begins-----------------------------------------------//

func TestCreateTppEmptyPolicy(t *testing.T) {
	data := testData{}
	data.zone = os.Getenv("TPP_PM_ROOT") + "\\\\" + RandTppPolicyName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(tppPolicyResourceTest, tokenProv, data.zone, data.filePath)
	t.Logf("Testing creating TPP empty Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating empty zone: ", data.zone)
					return checkCreateTppPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestCreateTppPolicy(t *testing.T) {
	data := testData{}
	data.zone = os.Getenv("TPP_PM_ROOT") + "\\\\" + RandTppPolicyName()

	data.filePath = GetAbsoluteFIlePath(policySpecTpp)

	config := fmt.Sprintf(tppPolicyResourceTest, tokenProv, data.zone, data.filePath)
	t.Logf("Testing creating TPP Zone:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating TPP zone: ", data.zone)
					return checkCreateCloudPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func checkCreateTppPolicy(t *testing.T, data *testData, s *terraform.State, validateAttr bool) error {
	t.Log("Validate Creating TPP empty policy", data.zone)

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

	if !validateAttr {
		return nil
	}

	//get policy on directory.
	file, err := os.Open(data.filePath)
	if err != nil {
		return err
	}

	fileBytes, err := ioutil.ReadAll(file)
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

	if *(filePolicySpecification.Default.Subject.Locality) != *(policySpecification.Default.Subject.Locality) {
		return fmt.Errorf("default locality is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Locality), *(policySpecification.Default.Subject.Locality))
	}

	return nil
}

//-------------------------------------------------TPP test cases ends------------------------------------------------//

/*
func TestRadPolicy(t *testing.T) {
	root_dir := GetRootDir()
	filePath := root_dir + "/test_files/emptyPolicy.json"
	config := fmt.Sprintf(readPolicy, cloudProvider, "vcert_cloud\\\\terraform-test", filePath)
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
	filePath := root_dir + "/test_files/emptyPolicy.json"
	config := fmt.Sprintf(readPolicy, cloudProvider, "vcert_cloud\\\\terraform-test", filePath)
	return config
}
*/
