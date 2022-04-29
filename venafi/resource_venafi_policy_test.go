package venafi

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"
)

//#nosec
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

	tokenProv = envVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`

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

	tppPolicyResourceTest = `
%s
resource "venafi_policy" "tpp_policy" {
	provider = "venafi"
	zone="%s"
	policy_specification = file("%s")
}
output "policy_specification" {
	value = "${venafi_policy.tpp_policy.policy_specification}"
}`

	readPolicy = `
%s
resource "venafi_policy" "read_policy" {
	provider = "venafi"
	zone="%s"
    policy_specification = file("%s")
}`
)

//-----------------------------------------------VaaS test cases begins----------------------------------------------//

func TestCreateVaasEmptyPolicy(t *testing.T) {
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(vaasPolicyResourceTest, vaasProv, data.zone, data.filePath)
	t.Logf("Testing Creating empty Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating VaaS empty zone: ", data.zone)
					return checkCreateVaasPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestCreateVaasPolicy(t *testing.T) {
	data := testData{}
	data.zone = RandAppName() + "\\\\" + RandCitName()

	data.filePath = GetAbsoluteFIlePath(policySpecVaas)

	config := fmt.Sprintf(vaasPolicyResourceTest, vaasProv, data.zone, data.filePath)
	t.Logf("Testing creating VaaS Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating VaaS zone: ", data.zone)
					return checkCreateVaasPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func checkCreateVaasPolicy(t *testing.T, data *testData, s *terraform.State, validateAttr bool) error {
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

	return nil
}

func TestImportVaasPolicy(t *testing.T) {
	config := getImportVaasConfig()
	t.Logf("Testing importing VaaS Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
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

	return nil
}

func getImportVaasConfig() string {
	path := GetAbsoluteFIlePath(policySpecVaas)
	zone := os.Getenv("CLOUD_POLICY_SAMPLE")
	zone = strings.Replace(zone, "\\", "\\\\", 1)
	config := fmt.Sprintf(readPolicy, vaasProv, zone, path)
	return config
}

//------------------------------------------------VaaS test cases ends------------------------------------------------//

//------------------------------------------------TPP test cases begins-----------------------------------------------//

func TestCreateTppEmptyPolicy(t *testing.T) {
	data := testData{}
	rootZone := os.Getenv("TPP_PM_ROOT")
	rootZone = strings.Replace(rootZone, "\\", "\\\\", 4)
	data.zone = rootZone + "\\\\" + RandTppPolicyName()

	data.filePath = GetAbsoluteFIlePath(emptyPolicy)

	config := fmt.Sprintf(tppPolicyResourceTest, tokenProv, data.zone, data.filePath)
	t.Logf("Testing creating TPP empty Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
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
	rootZone := os.Getenv("TPP_PM_ROOT")
	rootZone = strings.Replace(rootZone, "\\", "\\\\", 4)
	data.zone = rootZone + "\\\\" + RandTppPolicyName()

	data.filePath = GetAbsoluteFIlePath(policySpecTpp)

	config := fmt.Sprintf(tppPolicyResourceTest, tokenProv, data.zone, data.filePath)
	t.Logf("Testing creating TPP Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating TPP zone: ", data.zone)
					return checkCreateVaasPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestImportTppPolicy(t *testing.T) {
	config := getPolicyImportTppConfig()
	t.Logf("Testing importing TPP Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config:        config,
				ResourceName:  "venafi_policy.read_policy",
				ImportStateId: os.Getenv("TPP_PM_ROOT"),
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Logf("Checking zone: %s's attributes", os.Getenv("TPP_PM_ROOT"))
					return checkImportTppPolicy(states)
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

	return nil
}

func getPolicyImportTppConfig() string {
	path := GetAbsoluteFIlePath(policyReadSpecTpp)
	zone := os.Getenv("TPP_PM_ROOT")
	zone = strings.Replace(zone, "\\", "\\\\", 4)
	config := fmt.Sprintf(readPolicy, tokenProv, zone, path)
	return config
}

func checkImportTppPolicy(states []*terraform.InstanceState) error {
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
	path := GetAbsoluteFIlePath(policyReadSpecTpp)
	file, err := os.Open(path)
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

	domains := policy.ConvertToRegex(filePolicySpecification.Policy.Domains, *(filePolicySpecification.Policy.WildcardAllowed))

	equal := IsArrayStringEqual(domains, policySpecification.Policy.Domains)
	if !equal {
		return fmt.Errorf("domains are different, expected %+q but get %+q", filePolicySpecification.Policy.Domains, policySpecification.Policy.Domains)
	}

	if *(filePolicySpecification.Policy.WildcardAllowed) != *(policySpecification.Policy.WildcardAllowed) {
		return fmt.Errorf("wildcard allowed is different, expected %t but get %t", *(filePolicySpecification.Policy.WildcardAllowed), *(policySpecification.Policy.WildcardAllowed))
	}

	equal = IsArrayStringEqual(filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)

	if !equal {
		return fmt.Errorf("key types are different, expected %+q but get %+q", filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)
	}

	if *(filePolicySpecification.Default.Subject.Locality) != *(policySpecification.Default.Subject.Locality) {
		return fmt.Errorf("default locality is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Locality), *(policySpecification.Default.Subject.Locality))
	}

	if *(filePolicySpecification.Default.Subject.State) != *(policySpecification.Default.Subject.State) {
		return fmt.Errorf("default state is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.State), *(policySpecification.Default.Subject.State))
	}

	if *(filePolicySpecification.Default.Subject.Country) != *(policySpecification.Default.Subject.Country) {
		return fmt.Errorf("default state is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Country), *(policySpecification.Default.Subject.Country))
	}

	equal = IsArrayStringEqual(filePolicySpecification.Default.Subject.OrgUnits, policySpecification.Default.Subject.OrgUnits)

	if !equal {
		return fmt.Errorf("default org units are different, expected %+q but get %+q", filePolicySpecification.Default.Subject.OrgUnits, policySpecification.Default.Subject.OrgUnits)
	}

	if *(filePolicySpecification.Default.KeyPair.KeyType) != *(policySpecification.Default.KeyPair.KeyType) {
		return fmt.Errorf("default key type is different, expected %s but get %s", *(filePolicySpecification.Default.KeyPair.KeyType), *(policySpecification.Default.KeyPair.KeyType))
	}

	if *(filePolicySpecification.Default.KeyPair.RsaKeySize) != *(policySpecification.Default.KeyPair.RsaKeySize) {
		return fmt.Errorf("default rsa zise is different, expected %d but get %d", *(filePolicySpecification.Default.KeyPair.RsaKeySize), *(policySpecification.Default.KeyPair.RsaKeySize))
	}

	return nil
}

//-------------------------------------------------TPP test cases ends------------------------------------------------//
