package venafi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"os"
	"strings"
	"testing"
	"time"
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
	cloudProvider = environmentVariables + `
provider "venafi" {
	alias = "cloud"
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone = "${var.CLOUD_ZONE}"
}
`
	rsa2048 = `algorithm = "RSA"
               rsa_bits = "2048"`

	ecdsa521 = `algorithm = "ECDSA"
                ecdsa_curve = "P521"`

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
}`

	cloudConfig = `
%s
resource "venafi_certificate" "cloud_certificate" {
	provider = "venafi.cloud"
	common_name = "%s"
	%s
	key_password = "%s"
	expiration_window = %d
}
output "certificate" {
	value = "${venafi_certificate.cloud_certificate.certificate}"
}
output "private_key" {
	value = "${venafi_certificate.cloud_certificate.private_key_pem}"
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
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
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
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
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

func TestCloudSignedCert(t *testing.T) {
	t.Skip("waiting fix for cloud team") //todo: remove after TRS-6826
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(cloudConfig, cloudProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Cloud certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkStandardCert(t, &data, s)
					if err != nil {
						return err
					}
					return nil

				},
			},
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Testing Cloud certificate second run")
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

func TestCloudSignedCertUpdate(t *testing.T) {
	t.Skip("waiting fix for cloud team") //todo: remove after TRS-6826
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	// we have two checks: not_after - not_before >= expiration window [should raise error and exit] and now + expiration windows < not_after [should update cert]
	// tpp signs certificates on 80 hours. so we make windows the same size. it pass first check because it`s equal and failed second because script need some time for it works and update cert
	data.expiration_window = 80
	config := fmt.Sprintf(cloudConfig, cloudProvider, data.cn, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Cloud certificate with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
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
			r.TestStep{
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

func TestTPPSignedCertUpdate(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	// we have two checks: not_after - not_before >= expiration window [should raise error and exit] and now + expiration windows < not_after [should update cert]
	// tpp signs certificates on 8 years. so we make windows the same size. it pass first check because it`s equal and failed second because script need some time for it works and update cert
	data.expiration_window = 70080
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			r.TestStep{
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
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tppConfig, tppProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with RSA key with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			r.TestStep{
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

func TestTPPECDSASignedCert(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "123xxx"
	data.key_algo = ecdsa521
	data.expiration_window = 168
	config := fmt.Sprintf(tppConfig, tppProviderECDSA, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP certificate with ECDSA key  with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			r.TestStep{
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

func TestTokenSignedCertUpdate(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	// we have two checks: not_after - not_before >= expiration window [should raise error and exit] and now + expiration windows < not_after [should update cert]
	// tpp signs certificates on 8 years. so we make windows the same size. it pass first check because it`s equal and failed second because script need some time for it works and update cert
	data.expiration_window = 70080
	config := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with RSA key with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
				ExpectNonEmptyPlan: true,
			},
			r.TestStep{
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
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 168
	config := fmt.Sprintf(tokenConfig, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with RSA key with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			r.TestStep{
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
	data.private_key_password = "123xxx"
	data.key_algo = ecdsa521
	data.expiration_window = 168
	config := fmt.Sprintf(tokenConfig, tokenProviderECDSA, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing TPP Token certificate with ECDSA key with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			r.TestStep{
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
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 168
	cfEnvVarName := "TPP_CUSTOM_FIELDS"
	data.custom_fields = getCustomFields(cfEnvVarName)
	config := fmt.Sprintf(tokenConfigWithCustomFields, tokenProvider, data.cn, data.dns_ns, data.dns_ip, data.dns_email, data.key_algo, data.private_key_password, data.expiration_window, data.custom_fields)
	t.Logf("Testing TPP Token certificate with Custom Fields with config:\n %s", config)
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: config,
				Check: func(s *terraform.State) error {
					t.Log("Issuing TPP certificate with CN", data.cn)
					return checkStandardCert(t, &data, s)
				},
			},
			r.TestStep{
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

func getCustomFields(variableName string) string {
	formattedData := ""

	data := os.Getenv(variableName)
	entries := strings.Split(data, ",")
	for _, value := range entries {
		formattedData = formattedData + value + ",\n"
	}
	return formattedData
}

//TODO: make test with invalid key
//TODO: make test on invalid options fo RSA, ECSA keys
//TODO: make test with too big expiration window

func checkStandardCert(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Testing certificate with cn", data.cn)
	certUntyped := s.RootModule().Outputs["certificate"].Value
	certificate, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", certificate)
	if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	block, _ := pem.Decode([]byte(certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing cert: %s", err)
	}
	if expected, got := data.cn, cert.Subject.CommonName; got != expected {
		return fmt.Errorf("incorrect subject common name: expected %v, certificate %v", expected, got)
	}
	if len(data.dns_ns) > 0 {
		if expected, got := []string{data.cn, data.dns_ns}, cert.DNSNames; !sameStringSlice(got, expected) {
			return fmt.Errorf("incorrect DNSNames: expected %v, certificate %v", expected, got)
		}
	} else {
		if expected, got := []string{data.cn}, cert.DNSNames; !sameStringSlice(got, expected) {
			return fmt.Errorf("incorrect DNSNames: expected %v, certificate %v", expected, got)
		}
	}

	data.serial = cert.SerialNumber.String()
	data.timeCheck = time.Now().String()

	keyUntyped := s.RootModule().Outputs["private_key"].Value
	privateKey, ok := keyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"private_key\" is not a string")
	}

	t.Logf("Testing private key PEM:\n %s", privateKey)
	privKeyPEM, err := getPrivateKey([]byte(privateKey), data.private_key_password)

	_, err = tls.X509KeyPair([]byte(certificate), privKeyPEM)
	if err != nil {
		return fmt.Errorf("error comparing certificate and key: %s", err)
	}

	return nil
}

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
	renew, err := checkForRenew(*cert, 24)
	if err != nil {
		t.Log("error is", err.Error())
	} else if renew {
		t.Log("Certificate should be renewed in", renew)
	} else {
		t.Log("It's enough time until renew:", renew)
	}

	//return nil
}
