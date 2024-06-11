package venafi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

var (
	environmentVariables = fmt.Sprintf(`
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

	tppProvider = environmentVariables + `
provider "venafi" {
	alias = "tpp"
	url = "${var.TPP_URL}"
	tpp_username = "${var.TPP_USER}"
	tpp_password = "${var.TPP_PASSWORD}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tppProviderECDSA = environmentVariables + `
provider "venafi" {
	alias = "tpp"
	url = "${var.TPP_URL}"
	tpp_username = "${var.TPP_USER}"
	tpp_password = "${var.TPP_PASSWORD}"
	zone = "${var.TPP_ZONE_ECDSA}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tokenProvider = environmentVariables + `
provider "venafi" {
	alias = "token_tpp"
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tokenProviderECDSA = environmentVariables + `
provider "venafi" {
	alias = "token_tpp"
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE_ECDSA}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tppTokenProviderImport = environmentVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tppTokenProviderImportEmptyZone = environmentVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = ""
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	tppTokenProviderImportECDSA = environmentVariables + `
provider "venafi" {
	url = "${var.TPP_URL}"
	access_token = "${var.TPP_ACCESS_TOKEN}"
	zone = "${var.TPP_ZONE_ECDSA}"
	trust_bundle = "${file(var.TRUST_BUNDLE)}"
}`
	vaasProviderImport = environmentVariables + `
provider "venafi" {
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone = "${var.CLOUD_ZONE}"
}`
	vaasProvider = environmentVariables + `
provider "venafi" {
	alias = "vaas"
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone = "${var.CLOUD_ZONE}"
}
`

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

	vaasConfig = `
%s
resource "venafi_certificate" "vaas_certificate" {
	provider = "venafi.vaas"
	common_name = "%s"
	%s
	key_password = "%s"
	expiration_window = %d
}
output "certificate" {
	value = "${venafi_certificate.vaas_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.vaas_certificate.private_key_pem}"
	sensitive = true
}
output "expiration_window" {
	value = "${venafi_certificate.vaas_certificate.expiration_window}"
}`
	tppConfig = `
%s
resource "venafi_certificate" "tpp_certificate" {
	provider = "venafi.tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_email = [
		"%s"
	]
	%s
	key_password = "%s"
	expiration_window = %d
}
output "certificate" {
	value = "${venafi_certificate.tpp_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.tpp_certificate.private_key_pem}"
	sensitive = true
}`
	tppConfigWithNickname = `
%s
resource "venafi_certificate" "tpp_certificate" {
	provider = "venafi.tpp"
	common_name = "%s"
    nickname = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_email = [
		"%s"
	]
	%s
	key_password = "%s"
	expiration_window = %d
}`
	tokenConfig = `
%s
resource "venafi_certificate" "token_certificate" {
	provider = "venafi.token_tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_email = [
		"%s"
	]
	%s
	key_password = "%s"
	expiration_window = %d
}
output "certificate" {
	value = "${venafi_certificate.token_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.token_certificate.private_key_pem}"
	sensitive = true
}
output "expiration_window" {
	value = "${venafi_certificate.token_certificate.expiration_window}"
}`
	tokenConfigWithCustomFields = `
%s
resource "venafi_certificate" "token_certificate_custom_fields" {
	provider = "venafi.token_tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_email = [
		"%s"
	]
	%s
	key_password = "%s"
	expiration_window = %d
	custom_fields = {
		%s
	}
}
output "certificate" {
	value = "${venafi_certificate.token_certificate_custom_fields.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.token_certificate_custom_fields.private_key_pem}"
	sensitive = true
}`
	tokenValidDaysConfig = `
%s
resource "venafi_certificate" "token_certificate" {
	provider = "venafi.token_tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_email = [
		"%s"
	]
	%s
	key_password = "%s"
	expiration_window = %d
	issuer_hint = "%s"
	valid_days =   %d
}
output "certificate" {
	value = "${venafi_certificate.token_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.token_certificate.private_key_pem}"
	sensitive = true
}
output "expiration_window" {
	value = "${venafi_certificate.token_certificate.expiration_window}"
}`
	tppCsrServiceConfig = `
%s
resource "venafi_certificate" "token_certificate" {
	provider = "venafi.token_tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	key_password = "%s"
	csr_origin = "service"
}
output "certificate" {
	value = "${venafi_certificate.token_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.token_certificate.private_key_pem}"
	sensitive = true
}`

	tppCsrServiceConfigWithSans = `
%s
resource "venafi_certificate" "token_certificate" {
    provider = "venafi.token_tpp"
	common_name = "%s"
	san_dns = [
		"%s"
	]
	san_ip = [
		"%s"
	]
	san_uri = [
		"%s"
	]
	key_password = "%s"
	csr_origin = "service"
}
output "certificate" {
	value = "${venafi_certificate.token_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.token_certificate.private_key_pem}"
	sensitive = true
}
output "san_ip" {
	value = "${venafi_certificate.token_certificate.san_ip}"
}
output "san_uri" {
	value = "${venafi_certificate.token_certificate.san_uri}"
}`

	tppCsrServiceConfigImport = `
%s
resource "venafi_certificate" "token_tpp_certificate_import" {
	provider = "venafi"
}`
	vaasCsrServiceConfigImport = `
%s
resource "venafi_certificate" "token_vaas_certificate_import" {
	provider = "venafi"
}`

	vaasCsrServiceConfig = `
%s
resource "venafi_certificate" "vaas_certificate" {
	provider = "venafi.vaas"
	common_name = "%s"
	%s
	key_password = "%s"
	expiration_window = %d
	csr_origin = "service"
}
output "certificate" {
	value = "${venafi_certificate.vaas_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.vaas_certificate.private_key_pem}"
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

func TestVaasSignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(vaasConfig, vaasProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Vaas certificate with config:\n %s", config)
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
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing VaaS certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestVaasSignedCertUpdateRenew(t *testing.T) {
	/*
		This test focuses on the renewal feature. We need to set the expiration window to be the same as the certificate
		duration in order for the renew to take action. ExpectNonEmptyPlan is set true since we will always be able to
		update the certificate on terraform plan re-apply. This is applicable for test purposes only, in a real scenario
		the expiration window should not be too long, thus the terraform plan should be empty after a re-apply (once a
		renew re-apply is done after our plugin detected it should be renewed).

		We have two checks: not_after - not_before >= expiration window [should raise error and exit] and
		now + expiration windows < not_after [should update cert]
		VaaS zone creates certificates with duration of 1 week, so we make expiration_window the same size.
	*/
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 90 * 24 // 90 days
	//
	config := fmt.Sprintf(vaasConfig, vaasProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Cloud certificate with config:\n %s", config)
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
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate update")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare updated original certificate serial %s with updated %s", gotSerial, data.serial)
						if gotSerial == data.serial {
							return fmt.Errorf("serial number from updated certificate %s is the same as "+
								"in original number %s", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestVaasSignedCertUpdateSetGreaterExpWindow(t *testing.T) {
	/*
		We test to create a certificate on first step that has duration less from zone (without setting valid_days)
		than the expiration_window: It should create a Terraform state with an expiration_window  as same as the cert duration.
		On update, we expect a not empty plan due to the expiration_window being equal to cert duration, and the serial
		to be the same since creation of new resource was not applied.
	*/
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 60 * 24 // 60 days
	config := fmt.Sprintf(vaasConfig, vaasProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	data.expiration_window = 90*24 + 12 // 90 days + 12 hours
	configUpdate := fmt.Sprintf(vaasConfig, vaasProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing VaaS certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkStandardCertNew("venafi_certificate.vaas_certificate", t, &data),
					resource.TestCheckResourceAttr("venafi_certificate.vaas_certificate", "expiration_window", "1440"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkStandardCertNew("venafi_certificate.vaas_certificate", t, &data),
					resource.TestCheckResourceAttr("venafi_certificate.vaas_certificate", "expiration_window", "2172"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTPPSignedCertUpdate(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	// we have two checks: not_after - not_before >= expiration window [should raise error and exit] and now + expiration windows < not_after [should update cert]
	// tpp signs certificates on 8 years. so we make windows the same size.
	data.expiration_window = 70080
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate update")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare updated original certificate serial %s with updated %s", gotSerial, data.serial)
						if gotSerial == data.serial {
							return fmt.Errorf("serial number from updated certificate %s is the same as "+
								"in original number %s", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTPPSignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestTPPSignedCertWithNickname(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.nickname = data.cn + " - 1"
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tppConfigWithNickname, tppProvider, data.cn, data.nickname, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkStandardCertNew("venafi_certificate.tpp_certificate", t, &data),
					resource.TestCheckResourceAttr("venafi_certificate.tpp_certificate", venafiCertificateAttrNickname, data.nickname),
				),
			},
		},
	})
}

func TestTPPECDSASignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = ecdsa521
	data.expiration_window = 168
	config := fmt.Sprintf(tppConfig, tppProviderECDSA, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with ECDSA key  with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestTokenSignedCertUpdateRenew(t *testing.T) {
	/*
		This test focuses on the renewal feature. We need to set the expiration window to be the same as the certificate
		duration in order for the renew to take action. ExpectNonEmptyPlan is set true since we will always be able to
		update the certificate on terraform plan re-apply. This is applicable for test purposes only, in a real scenario
		the expiration window should not be too long, thus the terraform plan should be empty after a re-apply (once a
		renew re-apply is done after our plugin detected it should be renewed).

		We have two checks: not_after - not_before >= expiration window [should raise error and exit] and
		now + expiration windows < not_after [should update cert]
		TPP zone creates certificates with duration of 8 years. so we make expiration_window the same size.
	*/
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 70080
	config := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP Token certificate update")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare updated original certificate serial %s with updated %s", gotSerial, data.serial)
						if gotSerial == data.serial {
							return fmt.Errorf("serial number from updated certificate %s is the same as "+
								"in original number %s", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestTokenSignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestTokenECDSASignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = ecdsa521
	data.expiration_window = 168
	config := fmt.Sprintf(tokenConfig, tokenProviderECDSA, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with ECDSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestSignedCertCustomFields(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	cfEnvVarName := "TPP_CUSTOM_FIELDS"
	data.custom_fields = getCustomFields(cfEnvVarName)
	config := fmt.Sprintf(tokenConfigWithCustomFields, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window, data.custom_fields)
	t.Logf("Testing TPP Token certificate with Custom Fields with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestTokenSignedCertValidDays(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	hint := util.IssuerHintMicrosoft
	data.issuer_hint = hint.String()
	data.valid_days = validDays

	config := fmt.Sprintf(tokenValidDaysConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window, data.issuer_hint, data.valid_days)
	t.Logf("Testing TPP Token certificate's valid days with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN and valid days", data.cn)
					return checkCertValidDays(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					err := checkCertValidDays(t, &data, s)
					if err != nil {
						return err
					}

					return nil
				},
			},
		},
	})
}

func TestTokenSignedCertUpdateSetGreaterExpWindow(t *testing.T) {
	/*
		We test to create a certificate on first step that has duration less from zone (without setting valid_days)
		than the expiration_window: It should create a Terraform state with an expiration_window as same as the cert duration.
		On update, we expect a not empty plan due to the expiration_window being equal to zone validity duration, and the serial
		to be the same since creation of new resource was not applied.
	*/
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.expiration_window = 100
	config := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	data.expiration_window = 70080
	configUpdate := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkStandardCertNew("venafi_certificate.token_certificate", t, &data),
					resource.TestCheckResourceAttr("venafi_certificate.token_certificate", "expiration_window", "100"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkStandardCertNew("venafi_certificate.token_certificate", t, &data),
					resource.TestCheckResourceAttr("venafi_certificate.token_certificate", "expiration_window", "70080"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

//TODO: make test with invalid key
//TODO: make test on invalid options fo RSA, ECSA keys

func TestCheckForRenew(t *testing.T) {
	checkingCert := `
-----BEGIN CERTIFICATE-----
MIIFXTCCBEWgAwIBAgIKFeowvwAAAANfaDANBgkqhkiG9w0BAQsFADCBkTELMAkG
A1UEBhMCVVMxDTALBgNVBAgTBFV0YWgxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5
MRUwEwYDVQQKEwxWZW5hZmksIEluYy4xHzAdBgNVBAsTFkRlbW9uc3RyYXRpb24g
U2VydmljZXMxIjAgBgNVBAMTGVZlbmFmaSBFeGFtcGxlIElzc3VpbmcgQ0EwHhcN
MTkwMzIyMTQ0MTAyWhcNMTkwNDIxMTQ0MTAyWjCBgzELMAkGA1UEBhMCVVMxDTAL
BgNVBAgTBFV0YWgxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MRUwEwYDVQQKEwxW
ZW5hZmksIEluYy4xDTALBgNVBAsTBFJZQU4xJjAkBgNVBAMTHXJ5YW4tdGVycmFm
b3JtLnZlbmFmaS5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAu/ukMnzpaxhP8kQiYqtBMivaU5RMHpcsKPx/qkBp7JIuw7svxey2Gdhne0mA
DA02K9DsEXo/+cz0So6FCpeRiTR1yeA0BzsY4fALeOtD+Ebfl24OhcLRilbriFZB
p6zweWE3f4XYgXMtpPXZX4osfbfYsqU5S0L+qqU69+DPhEfiFj2XYm9PSeIybNX2
IipxEvOwXN/RB3QKw8tsC6EeUwkadTVgzLURh7wFsod4EkAVUsqC3StWXhd2OJEB
zSjWj2tbWce3AmaNZMnhiGzxn48pz37j7CV5gwwwDgGkcg5UFf8SnkPNCzvKTcu2
CnRz5QttEI7rszPy417kAMfrPQIDAQABo4IBwTCCAb0wagYDVR0RBGMwYYIfcnlh
bi10ZXJyYWZvcm0tMS52ZW5hZmkuZXhhbXBsZYIfcnlhbi10ZXJyYWZvcm0tMi52
ZW5hZmkuZXhhbXBsZYIdcnlhbi10ZXJyYWZvcm0udmVuYWZpLmV4YW1wbGUwHQYD
VR0OBBYEFP9T6Ds8fcW+o5CG8NeJqb8EQMkxMB8GA1UdIwQYMBaAFP8knpZ6L+nN
/70NEe6/paB2TYeyMFIGA1UdHwRLMEkwR6BFoEOGQWh0dHA6Ly9wa2kudmVuYWZp
LmV4YW1wbGUvY3JsL1ZlbmFmaSUyMEV4YW1wbGUlMjBJc3N1aW5nJTIwQ0EuY3Js
MDoGCCsGAQUFBwEBBC4wLDAqBggrBgEFBQcwAYYeaHR0cDovL3BraS52ZW5hZmku
ZXhhbXBsZS9vY3NwMA4GA1UdDwEB/wQEAwIFoDA9BgkrBgEEAYI3FQcEMDAuBiYr
BgEEAYI3FQiEgMsZhO+xJISdnx6G8PlSh8/iEwSChu8MgbLiZwIBZAIBAjATBgNV
HSUEDDAKBggrBgEFBQcDATAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMBMA0G
CSqGSIb3DQEBCwUAA4IBAQCtMA9zMFOZ9fhXS7JWpiZNCQSQ731qxw5M/+F2OkoM
FJ2QiLzOmocyi5UzqnH2joSd0zoea8J68MMC+DCSaWNtBXPETqn0zEwJ9fS2RPA8
hJqlPKWU43UXnIUxTHOqCVxvHrLCI4Y6a4IKyG3hcTHWfOxUjO/PLIEcU+vt5Qf/
qtWSqayqM2EKrNEKcexwV/csZs1n8C9eoMn5mn4uS/XgZ42+dJeXbeTk7MR10H9G
niEgPgNh7FcQZ9/Y3YkJnf6IYGMREkGnCxKEtkjhmiLvZq2B41t7IaWVh8A9oe2w
re33mo74mGFv4rpxWk249YXvEbskI8VS83IAhMrUENR0
-----END CERTIFICATE-----`
	t.Log("Cehc cert", checkingCert)
	cert2 := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAI7dxrBnlT6ZMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTkwMzIyMTYyNzM2WhcNMTkwMzIzMTYyNzM2WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAxH0VtAZv64amWPkA75qqZ6X54T/u4gDYSMnekLQco1sxRM2VMvY737YT
pbuVhBiT8hEqMgViu3TNnQVkjuk32fyw1n/zX1uS83ZU2nKHgFokS1UL61xCgrbS
o5sCA+hHj9+VnjO+r/WtRjca4JoL91w1o37kYLmAAGniG7PiyuKGjkVjoZ4REwii
qIvM2mGqLYKJkIo8Y7pQ+QUrbIRfOY5fi+ECxHCCjx/Ftj/WyB3tWjsLQovEQ+XN
lqAI8VUqGo+WI9CK6JB8k6GVxvwhCwz2v9E6YKKrU+6eGYbIsvoBdz6XGXSb0Ic5
kIbEIfh+zCfjR68CFRHt9Fnvmw6ulwIDAQABo1AwTjAdBgNVHQ4EFgQUs40zh87s
eGdrfJGXOUxfx6tHvLswHwYDVR0jBBgwFoAUs40zh87seGdrfJGXOUxfx6tHvLsw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAu64/IUpAnnLIw5EE/TGt
SJ/pmTKjomiIReHZb4bQg2FbtB7wdh5uehDoYNTBMC50o7UMUyG3pdKV+omBuk4R
rrWnWNJHA8FXxmpjZCDt2lNvGz9tR5o2+/pYvebrJfmsgLoTzFJOtFUJBUO041sF
bkS4WyyHpoqDk2JAFaEKLaCqZ1LupWxVRo+KFCF5/K9Hj7Ox8B/yWuF+7EXxkiBT
xchFP5MdLKv+PWW4uC/sl4x+hEjPPUqwEseU+v30HePpm5OieKNnk7zm5OEARwnd
G08wfP9Mj/c1z7/5virv5+pz/qS1vc5qXP+8OHCN0hVNJhSOy60ttG4Nli/eBaCJ
xA==
-----END CERTIFICATE-----
`
	block, _ := pem.Decode([]byte(cert2))
	cert, _ := x509.ParseCertificate(block.Bytes)
	renew := checkForRenew(*cert, 24)
	if renew {
		t.Log("Certificate should be renewed in", renew)
	}
	t.Log("It's enough time until renew:", renew)
}

func TestTppCsrService(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"

	config := fmt.Sprintf(tppCsrServiceConfig, tokenProvider, data.cn, data.dns_ns, data.private_key_password)
	t.Logf("Testing TPP Token certificate with Service CSR generated and config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CSR Service Generated", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
		},
	})
}

func TestVaasCsrService(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "FooB4rNew4$x"
	data.expiration_window = 48
	data.key_algo = rsa2048

	config := fmt.Sprintf(vaasCsrServiceConfig, vaasProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing VaaS certificate with CSR service and config:\n %s", config)
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

func TestImportCertificateTpp(t *testing.T) {
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	name := "import"
	data := getCertTppImportConfig(name)
	createCertificate(t, cfg, data, true)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	importId := fmt.Sprintf("%s,%s", data.cn, data.private_key_password)
	t.Logf("Testing importing TPP cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing TPP certificate with CSR Service Generated", data.cn)
					return checkStandardImportCert(t, data, states)
				},
			},
		},
	})
}

func TestImportCertificateTppWithNickname(t *testing.T) {
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.nickname = data.cn + " - 1"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.expiration_window = 100
	createCertificate(t, cfg, &data, true)

	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	importId := fmt.Sprintf("%s,%s", data.nickname, data.private_key_password)
	t.Logf("Testing importing TPP cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing TPP certificate with CSR Service Generated", data.cn)
					return checkImportWithObjectName(t, &data, states)
				},
			},
		},
	})
}

func TestImportCertificateTppWithCustomFields(t *testing.T) {
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	data := getCertTppImportConfigWithCustomFields()
	cfEnvVarName := "TPP_CUSTOM_FIELDS"
	data.custom_fields = getCustomFields(cfEnvVarName)
	createCertificate(t, cfg, data, true)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	importId := fmt.Sprintf("%s,%s", data.cn, data.private_key_password)
	t.Logf("Testing importing TPP cert with custom fields:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing TPP certificate with CSR Service Generated", data.cn)
					return checkImportTppCertWithCustomFields(t, data, states)
				},
			},
		},
	})
}

func TestImportCertificateECDSA(t *testing.T) {
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	name := "import.ecdsa"
	data := getCertTppImportConfig(name)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImportECDSA)
	data.zone = os.Getenv("TPP_ZONE_ECDSA")
	createCertificate(t, cfg, data, true)
	importId := fmt.Sprintf("%s,%s", data.cn, data.private_key_password)
	t.Logf("Testing importing TPP cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing TPP certificate with CSR Service Generated", data.cn)
					return checkStandardImportCert(t, data, states)
				},
			},
		},
	})
}

func TestImportCertificateVaas(t *testing.T) {
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
	}
	data := getCertVaasImportConfig()
	pickupId := createCertificate(t, cfg, data, true)
	config := fmt.Sprintf(vaasCsrServiceConfigImport, vaasProviderImport)
	importId := fmt.Sprintf("%s,%s", pickupId, data.private_key_password)
	t.Logf("Testing importing VaaS cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_vaas_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing VaaS certificate with CSR Service Generated", data.cn)
					return checkStandardImportCert(t, data, states)
				},
			},
		},
	})
}

func TestValidateWrongImportEntries(t *testing.T) {
	name := "import"
	data := getCertTppImportConfig(name)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	configWithoutZone := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImportEmptyZone)
	t.Logf("Testing importing TPP cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: fmt.Sprintf("%s,%s,exceeded", data.cn, data.private_key_password),
				ImportState:   true,
				ExpectError:   regexp.MustCompile(importIdFailExceededValues),
			},
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: fmt.Sprintf("%s,", data.cn),
				ImportState:   true,
				ExpectError:   regexp.MustCompile(importKeyPasswordFailEmpty),
			},
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: fmt.Sprintf(",%s", data.private_key_password),
				ImportState:   true,
				ExpectError:   regexp.MustCompile(importPickupIdFailEmpty),
			},
			{
				Config:        configWithoutZone,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: fmt.Sprintf("%s,%s", data.cn, data.private_key_password),
				ImportState:   true,
				ExpectError:   regexp.MustCompile(importZoneFailEmpty),
			},
		},
	})
}

func TestManyCertsTpp(t *testing.T) {
	// test for removing workaround of VEN-46960
	t.Log("Testing stressing TPP with many certs with same certificate object (same common name)")
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.many.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate third run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after third run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from third run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate fourth run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after fourth run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from fourth run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate fifth run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after fifth run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from fifth run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestManyCertsTppCsrService(t *testing.T) {
	// test for removing workaround of VEN-46960
	t.Log("Testing stressing TPP with many certificates with CSR Service Generated and same certificate object (same common name)")
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.many.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"

	config := fmt.Sprintf(tppCsrServiceConfig, tokenProvider, data.cn, data.dns_ns, data.private_key_password)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate second run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after second run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from second run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate third run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after third run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from third run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate fourth run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after fourth run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from fourth run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing TPP certificate fifth run")
					gotSerial := data.serial
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					} else {
						t.Logf("Compare certificate serial %s with serial after fifth run %s", gotSerial, data.serial)
						if gotSerial != data.serial {
							return fmt.Errorf("serial number from fifth run %s is different as in original number %s."+
								" Which means that certificate was updated without reason", data.serial, gotSerial)
						} else {
							return nil
						}
					}
				},
			},
		},
	})
}

func TestTppSansCsrService(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.san_uri = "https://www.abc.venafi.com"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "FooB4rNew4$x"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tppCsrServiceConfigWithSans, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.san_uri, data.private_key_password)
	t.Logf("Testing TPP Token certificate with Custom Fields with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					}
					err = checkCertSans(t, &data, s)
					if err != nil {
						return err
					}
					return nil
				},
			},
		},
	})
}
