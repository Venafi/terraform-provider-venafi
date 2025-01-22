//go:build tpp
// +build tpp

package venafi

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var (
	envSshCertVariables = fmt.Sprintf(`
variable "TPP_USER" {default = "%s"}
variable "TPP_PASSWORD" {default = "%s"}
variable "TPP_URL" {default = "%s"}
variable "TPP_ZONE" {default = "%s"}
variable "TRUST_BUNDLE" {default = "%s"}
variable "TPP_ACCESS_TOKEN" {default = "%s"}
`,
		os.Getenv("TPP_USER"),
		os.Getenv("TPP_PASSWORD"),
		os.Getenv("TPP_URL"),
		os.Getenv("TPP_ZONE"),
		os.Getenv("TRUST_BUNDLE"),
		os.Getenv("TPP_ACCESS_TOKEN"))

	tokenSshCertProv = envSshCertVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`

	tppSshCertResourceTest = `
%s
resource "venafi_ssh_certificate" "test" {
	provider = "venafi"
	key_id="%s"
	template="%s"
	public_key_method="%s"
	valid_hours = %s
	principal=[
		%s
	]
	source_address=[
		"%s"
	]
}`
	tppSshCertResourceTestNewAttrPrincipals = `
%s
resource "venafi_ssh_certificate" "test-new-principals" {
	provider = "venafi"
	key_id="%s"
	template="%s"
	public_key_method="%s"
	valid_hours = %s
	principals=[
		%s
	]
	source_address=[
		"%s"
	]
}`
)

func TestTPPSshCert(t *testing.T) {
	t.Parallel()
	t.Log("Testing creating ssh certificate")

	data := getTestData()
	data.publicKeyMethod = "service"

	// data.principals only holds the values for principals, actually we are testing "principal" attribute defined at the resource.
	config := fmt.Sprintf(tppSshCertResourceTest, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSshCertificate("venafi_ssh_certificate.test", t, &data),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTPPSshCertNewAttrPrincipals(t *testing.T) {
	t.Parallel()
	t.Log("Testing creating ssh certificate with new attribute for principals")

	data := getTestData()
	data.publicKeyMethod = "service"

	config := fmt.Sprintf(tppSshCertResourceTestNewAttrPrincipals, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSshCertificate("venafi_ssh_certificate.test-new-principals", t, &data),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTPPSshCertLocalPublicKey(t *testing.T) {
	t.Parallel()
	t.Log("Testing creating ssh certificate")

	data := getTestData()
	data.publicKeyMethod = "local"

	// data.principals only holds the values for principals, actually we are testing "principal" attribute defined at the resource.
	config := fmt.Sprintf(tppSshCertResourceTest, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSshCertificate("venafi_ssh_certificate.test", t, &data),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTPPSshCertLocalPublicKeyNewAttrPrincipals(t *testing.T) {
	t.Parallel()
	t.Log("Testing creating ssh certificate with new attribute for principals")

	data := getTestData()
	data.publicKeyMethod = "local"

	config := fmt.Sprintf(tppSshCertResourceTestNewAttrPrincipals, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSshCertificate("venafi_ssh_certificate.test-new-principals", t, &data),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func checkSshCertificate(resourceName string, t *testing.T, data *testData) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		t.Log("Testing SSH certificate with key-id", data.keyId)
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}
		certificate := rs.Primary.Attributes["certificate"]
		if certificate == "" {
			return fmt.Errorf("certificate is empty")
		}
		privateKey := rs.Primary.Attributes["private_key"]
		if privateKey == "" {
			return fmt.Errorf("private key is empty")
		}

		publicKey := rs.Primary.Attributes["public_key"]
		if publicKey == "" {
			return fmt.Errorf("certificate is empty")
		}

		principalsLengthString := rs.Primary.Attributes["principals.#"]
		var principalsLength int
		var err error
		principalsLength = 0
		if principalsLengthString != "" {
			principalsLength, err = strconv.Atoi(principalsLengthString)
			if err != nil {
				return fmt.Errorf("error getting length: %s", err)
			}
		}
		if principalsLength == 0 {
			var principalLength int
			var err error
			principalLength = 0
			principalLengthString := rs.Primary.Attributes["principal.#"]
			if principalLengthString != "" {
				principalLength, err = strconv.Atoi(principalLengthString)
				if err != nil {
					return fmt.Errorf("error getting length: %s", err)
				}
			}
			if principalLength == 0 && data.principals != "" {
				return fmt.Errorf("principal list is empty")
			}
		}
		return nil
	}
}

func getTestData() testData {
	return testData{
		keyId:          RandTppSshCertName(),
		template:       os.Getenv("TPP_SSH_CA"),
		sourceAddress:  "test.com",
		validityPeriod: "4",
		principals:     "\"" + strings.Join([]string{"bob", "alice"}, `", "`) + "\"",
	}
}
