//go:build tpp
// +build tpp

package venafi

import (
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
variable "TPP_ACCESS_TOKEN" {default = "%s"}
`,
		os.Getenv("TPP_USER"),
		os.Getenv("TPP_PASSWORD"),
		os.Getenv("TPP_URL"),
		os.Getenv("TPP_ZONE"),
		os.Getenv("TPP_ZONE_ECDSA"),
		os.Getenv("TRUST_BUNDLE"),
		os.Getenv("TPP_ACCESS_TOKEN"),
	)

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
)

func TestTPPSignedCertUpdate(t *testing.T) {
	t.Parallel()
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
	// CyberArk Certificate Manager, Self-Hosted signs certificates on 8 years. so we make windows the same size.
	data.expiration_window = 70080
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate update")
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
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with RSA key with config:\n %s", config)
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
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with ECDSA key  with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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

func TestTPPTokenSignedCertUpdateRenew(t *testing.T) {
	/*
		This test focuses on the renewal feature. We need to set the expiration window to be the same as the certificate
		duration in order for the renew to take action. ExpectNonEmptyPlan is set true since we will always be able to
		update the certificate on terraform plan re-apply. This is applicable for test purposes only, in a real scenario
		the expiration window should not be too long, thus the terraform plan should be empty after a re-apply (once a
		renew re-apply is done after our plugin detected it should be renewed).

		We have two checks: not_after - not_before >= expiration window [should raise error and exit] and
		now + expiration windows < not_after [should update cert]
		CyberArk Certificate Manager, Self-Hosted zone creates certificates with duration of 8 years. so we make expiration_window the same size.
	*/
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted Token certificate update")
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

func TestTPPTokenSignedCert(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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

func TestTPPTokenECDSASignedCert(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with ECDSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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

func TestTPPSignedCertCustomFields(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with Custom Fields with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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

func TestTPPTokenSignedCertValidDays(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate's valid days with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN and valid days", data.cn)
					return checkCertValidDays(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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

func TestTPPTokenSignedCertUpdateSetGreaterExpWindow(t *testing.T) {
	/*
		We test to create a certificate on first step that has duration less from zone (without setting valid_days)
		than the expiration_window: It should create a Terraform state with an expiration_window as same as the cert duration.
		On update, we expect a not empty plan due to the expiration_window being equal to zone validity duration, and the serial
		to be the same since creation of new resource was not applied.
	*/
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with config:\n %s", config)
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

func TestTPPTppCsrService(t *testing.T) {
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"

	config := fmt.Sprintf(tppCsrServiceConfig, tokenProvider, data.cn, data.dns_ns, data.private_key_password)
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with Service CSR generated and config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CSR Service Generated", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
		},
	})
}

func TestTPPValidateWrongImportEntries(t *testing.T) {
	t.Parallel()
	name := "import"
	data := getCertTppImportConfig(name)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	configWithoutZone := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImportEmptyZone)
	t.Logf("Testing importing CyberArk Certificate Manager, Self-Hosted cert:\n %s", config)
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

func TestTPPImportCertificate(t *testing.T) {
	t.Parallel()
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
					t.Log("Importing CyberArk Certificate Manager, Self-Hosted certificate with CSR Service Generated", data.cn)
					return checkStandardImportCert(t, data, states)
				},
			},
		},
	})
}

func TestTPPImportCertificateWithNickname(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing importing CyberArk Certificate Manager, Self-Hosted cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing CyberArk Certificate Manager, Self-Hosted certificate with CSR Service Generated", data.cn)
					return checkImportWithObjectName(t, &data, states)
				},
			},
		},
	})
}

func TestTPPImportCertificateWithCustomFields(t *testing.T) {
	t.Parallel()
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	data := getCertTppImportConfigWithCustomFields()
	cfEnvVarName := "TPP_CUSTOM_FIELDS"
	data.custom_fields = getCustomFields(cfEnvVarName)
	createCertificate(t, cfg, data, true)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImport)
	importId := fmt.Sprintf("%s,%s", data.cn, data.private_key_password)
	t.Logf("Testing importing CyberArk Certificate Manager, Self-Hosted cert with custom fields:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing CyberArk Certificate Manager, Self-Hosted certificate with CSR Service Generated", data.cn)
					return checkImportTppCertWithCustomFields(t, data, states)
				},
			},
		},
	})
}

func TestTPPImportCertificateECDSA(t *testing.T) {
	t.Parallel()
	var cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
	}
	name := "import.ecdsa"
	data := getCertTppImportConfig(name)
	config := fmt.Sprintf(tppCsrServiceConfigImport, tppTokenProviderImportECDSA)
	data.zone = os.Getenv("TPP_ZONE_ECDSA")
	createCertificate(t, cfg, data, true)
	importId := fmt.Sprintf("%s,%s", data.cn, data.private_key_password)
	t.Logf("Testing importing CyberArk Certificate Manager, Self-Hosted cert:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "venafi_certificate.token_tpp_certificate_import",
				ImportStateId: importId,
				ImportState:   true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					t.Log("Importing CyberArk Certificate Manager, Self-Hosted certificate with CSR Service Generated", data.cn)
					return checkStandardImportCert(t, data, states)
				},
			},
		},
	})
}

func TestTPPManyCerts(t *testing.T) {
	t.Parallel()
	// test for removing workaround of VEN-46960
	t.Log("Testing stressing CyberArk Certificate Manager, Self-Hosted with many certs with same certificate object (same common name)")
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate third run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate fourth run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate fifth run")
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

func TestTPPManyCertsCsrService(t *testing.T) {
	t.Parallel()
	// test for removing workaround of VEN-46960
	t.Log("Testing stressing CyberArk Certificate Manager, Self-Hosted with many certificates with CSR Service Generated and same certificate object (same common name)")
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.many.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"

	config := fmt.Sprintf(tppCsrServiceConfig, tokenProvider, data.cn, data.dns_ns, data.private_key_password)
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted certificate with RSA key with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate second run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate third run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate fourth run")
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
					t.Log("Testing CyberArk Certificate Manager, Self-Hosted certificate fifth run")
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

func TestTPPSansCsrService(t *testing.T) {
	t.Parallel()
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
	t.Logf("Testing CyberArk Certificate Manager, Self-Hosted Token certificate with Custom Fields with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing CyberArk Certificate Manager, Self-Hosted certificate with CN", data.cn)
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
