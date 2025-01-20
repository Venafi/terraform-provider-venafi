//go:build tpp
// +build tpp

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
variable "TPP_USER" {default = "%s"}
variable "TPP_PASSWORD" {default = "%s"}
variable "TPP_URL" {default = "%s"}
variable "TPP_ZONE" {default = "%s"}
variable "TPP_ZONE_ECDSA" {default = "%s"}
variable "TRUST_BUNDLE" {default = "%s"}
variable "TPP_ACCESS_TOKEN" {default = "%s"}
`,
		os.Getenv("TPP_USER"),
		os.Getenv("TPP_PASSWORD"),
		os.Getenv("TPP_URL"),
		os.Getenv("TPP_ZONE"),
		os.Getenv("TPP_ZONE_ECDSA"),
		os.Getenv("TRUST_BUNDLE"),
		os.Getenv("TPP_ACCESS_TOKEN"))

	tokenProv = envVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
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

func TestTPPCreateEmptyPolicy(t *testing.T) {
	t.Parallel()
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
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating empty zone: ", data.zone)
					return checkCreateTppPolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestTPPCreatePolicy(t *testing.T) {
	t.Parallel()
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
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Creating TPP zone: ", data.zone)
					return checkCreatePolicy(t, &data, s, false)
				},
			},
		},
	})
}

func TestTPPImportPolicy(t *testing.T) {
	t.Parallel()
	config := getPolicyImportTppConfig()
	t.Logf("Testing importing TPP Zone:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
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

	fileBytes, err := io.ReadAll(file)
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
