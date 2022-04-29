package venafi

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"testing"
)

var (
	envSshConfigVariables = fmt.Sprintf(`
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

	tokenSshConfigProv = envSshConfigVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`

	tppSshConfigResourceTest = `
%s
resource "venafi_ssh_config" "test" {
	provider = "venafi"
	template="%s"
}
output "ca_public_key"{
	value = venafi_ssh_config.test.ca_public_key
}
output "principals"{
	value = venafi_ssh_config.test.principals
}`
)

func TestSshConfig(t *testing.T) {
	t.Log("Testing getting ssh config that returns the CA Public Key and the principals from TPP")

	data := getTestConfigData()

	config := fmt.Sprintf(tppSshConfigResourceTest, tokenSshConfigProv, data.template)
	t.Logf("Testing SSH config with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkSshCaPubKey(t, &data, s)
					if err != nil {
						return err
					}
					err = checkSshPrincipals(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
			},
		},
	})
}

func checkSshCaPubKey(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Checking for CA public key", data.template)
	caPubKeyUntyped := s.RootModule().Outputs["ca_public_key"].Value
	caPubKey, ok := caPubKeyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"ca_pub_key\" is not a string")
	}
	if caPubKey == "" {
		return fmt.Errorf("The CA public key attribute \"ca_pub_key\" is empty")
	}
	return nil
}

func checkSshPrincipals(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Checking for principals", data.template)
	principalUntyped := s.RootModule().Outputs["principals"].Value
	err := validateStringListFromSchemaAttribute(principalUntyped, "principals")
	if err != nil {
		return err
	}
	return nil
}

func getTestConfigData() testData {
	return testData{
		template: os.Getenv("TPP_SSH_CA"),
	}
}
