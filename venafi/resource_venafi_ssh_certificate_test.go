package venafi

import (
	"fmt"
	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"os"
	"strings"
	"testing"
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

	tokenSshCertProv = environmentVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`

	tppSshCertResourceTest = `
%s
resource "venafi_ssh_certificate" "test1" {
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
}

output "certificate"{
	value = venafi_ssh_certificate.test1.certificate
}
output "public_key"{
	value = venafi_ssh_certificate.test1.public_key
}
output "private_key"{
	value = venafi_ssh_certificate.test1.private_key
}
output "principals"{
	value = venafi_ssh_certificate.test1.principal
}`
	tppSshCertResourceTestNewAttrPrincipals = `
%s
resource "venafi_ssh_certificate" "test2" {
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
}

output "certificate"{
	value = venafi_ssh_certificate.test2.certificate
}
output "public_key"{
	value = venafi_ssh_certificate.test2.public_key
}
output "private_key"{
	value = venafi_ssh_certificate.test2.private_key
}
output "principals"{
	value = venafi_ssh_certificate.test2.principals
}`
)

func TestSshCert(t *testing.T) {
	t.Log("Testing creating ssh certificate")

	data := getTestData()
	data.publicKeyMethod = "service"

	// data.principals only holds the values for principals, actually we are testing "principal" attribute defined at the resource.
	config := fmt.Sprintf(tppSshCertResourceTest, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkSshCertificate(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestSshCertNewAttrPrincipals(t *testing.T) {
	t.Log("Testing creating ssh certificate with new attribute for principals")

	data := getTestData()
	data.publicKeyMethod = "service"

	config := fmt.Sprintf(tppSshCertResourceTestNewAttrPrincipals, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkSshCertificate(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestSshCertLocalPublicKey(t *testing.T) {
	t.Log("Testing creating ssh certificate")

	data := getTestData()
	data.publicKeyMethod = "local"

	// data.principals only holds the values for principals, actually we are testing "principal" attribute defined at the resource.
	config := fmt.Sprintf(tppSshCertResourceTest, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkSshCertificate(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestSshCertLocalPublicKeyNewAttrPrincipals(t *testing.T) {
	t.Log("Testing creating ssh certificate with new attribute for principals")

	data := getTestData()
	data.publicKeyMethod = "local"

	config := fmt.Sprintf(tppSshCertResourceTestNewAttrPrincipals, tokenSshCertProv, data.keyId, data.template, data.publicKeyMethod, data.validityPeriod, data.principals, data.sourceAddress)
	t.Logf("Testing SSH certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkSshCertificate(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func checkSshCertificate(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Testing SSH certificate with key-id", data.keyId)
	certUntyped := s.RootModule().Outputs["certificate"].Value
	certificate, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}
	if certificate == "" {
		return fmt.Errorf("certificate is empty")
	}

	privKeyUntyped := s.RootModule().Outputs["private_key"].Value
	privateKey, ok := privKeyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"private key\" is not a string")
	}
	if privateKey == "" {
		return fmt.Errorf("private key is empty")
	}

	pubKeyUntyped := s.RootModule().Outputs["public_key"].Value
	publicKey, ok := pubKeyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}
	if publicKey == "" {
		return fmt.Errorf("certificate is empty")
	}

	principalsUntyped := s.RootModule().Outputs["principals"].Value
	principals, ok := principalsUntyped.([]interface{})
	if !ok {
		if len(principals) <= 0 {
			fmt.Errorf("\"principals\" list is empty")
		}
		for _, principal := range principals {
			principalString, ok := principal.(string)
			if !ok {
				fmt.Errorf("value inside \"principals\" returned not string value")
			}
			if principalString == "" {
				fmt.Errorf("value inside principals\" is empty string")
			}
		}
	}

	return nil
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
