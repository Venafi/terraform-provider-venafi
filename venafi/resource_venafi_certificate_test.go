package venafi

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var (
	devConfig = `
provider "venafi" {
	alias = "dev"
	dev_mode = true
}
resource "venafi_certificate" "dev_certificate" {
	provider = "venafi.dev"
	common_name = "%s"
	%s
	san_dns = [
		"%s"
	]
	san_ip = [
		"10.1.1.1",
		"192.168.0.1"
	]
	san_email = [
		"dev@venafi.com",
		"dev2@venafi.com"
	]
}
output "certificate" {
	value = "${venafi_certificate.dev_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.dev_certificate.private_key_pem}"
	sensitive = true
}`
)

func TestDevSignedCert(t *testing.T) {
	t.Log("Testing Dev RSA certificate")
	data := testData{}
	data.cn = "dev-random.venafi.example.com"
	data.dns_ns = "dev-web01-random.example.com"
	data.key_algo = rsa2048
	config := fmt.Sprintf(devConfig, data.cn, data.key_algo, data.dns_ns)
	t.Logf("Testing dev certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
			},
		},
	})
}

func TestDevSignedCertECDSA(t *testing.T) {
	t.Log("Testing Dev ECDSA certificate")
	data := testData{}
	data.cn = "dev-random.venafi.example.com"
	data.dns_ns = "dev-web01-random.example.com"
	data.key_algo = ecdsa521
	config := fmt.Sprintf(devConfig, data.cn, data.key_algo, data.dns_ns)
	t.Logf("Testing dev certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
			},
		},
	})
}
