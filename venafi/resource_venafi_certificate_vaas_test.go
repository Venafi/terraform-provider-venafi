//go:build vaas
// +build vaas

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
)

const (
	VcertErrorLocalCsrUnacceptableOu   = "Distinguished name component OU with value \"%s\" is invalid"
	VcertErrorServiceCsrUnacceptableOu = "(.)+specified org unit  \\[%s\\], doesn't match with policy's specified org unit(.)+"
)

var (
	environmentVariables = fmt.Sprintf(`
variable "CLOUD_URL" {default = "%s"}
variable "CLOUD_APIKEY" {default = "%s"}
variable "CLOUD_ZONE" {default = "%s"}
variable "CLOUD_ZONE_RESTRICTED_2" {default = "%s"}
`,
		os.Getenv("CLOUD_URL"),
		os.Getenv("CLOUD_APIKEY"),
		os.Getenv("CLOUD_ZONE"),
		os.Getenv("CLOUD_ZONE_RESTRICTED_2"),
	)

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
	vaasProviderCITRestricted = environmentVariables + `
provider "venafi" {
	alias = "vaas"
	url = "${var.CLOUD_URL}"
	api_key = "${var.CLOUD_APIKEY}"
	zone = "${var.CLOUD_ZONE_RESTRICTED_2}"
}
`

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
	vaasConfigForDnCSRLocalGenerated = `
%s
resource "venafi_certificate" "vaas_certificate" {
	provider = "venafi.vaas"
	common_name = "%s"
	organizational_units = [
		"%s",
		"%s"
	]
	country = "%s"
	state = "%s"
    locality = "%s"
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
	vaasConfigForDnCSRServiceGenerated = `
%s
resource "venafi_certificate" "vaas_certificate" {
	provider = "venafi.vaas"
	common_name = "%s"
	organizational_units = [
		"%s",
		"%s"
	]
	country = "%s"
	state = "%s"
    locality = "%s"
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
}
output "expiration_window" {
	value = "${venafi_certificate.vaas_certificate.expiration_window}"
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

func TestVAASSignedCert(t *testing.T) {
	t.Parallel()
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

// This test is to confirm the added support for the Certificate Signing Request DN(Distinguished Name).
// The used TLSPC zone (certificate issuing template) is configured with a set of specific values for the CSR Parameters
// (Organization, Organizational Units, City, State and Country) and with Recommended Settings values being a subset of
// the CSR Parameters values.
// Following a table showing the expected behaviour and the expected values that the resulting certificate will contain
// for the O, OU, L, ST, C parameters
// +==========================+===================================+====================================================+======================+===================================+
// |                          | Terraform venafi_certificate      | CIT configuration                                  | Recommended Settings | Resulting Certificate             |
// +==========================+===================================+====================================================+======================+===================================+
// | Organization(O)          |                                   | Venafi Inc.                                        | Venafi Inc.          | Venafi Inc.                       |
// | Organizational Units(OU) | Professional Services;Engineering | Customer Support;Professional Services;Engineering | Customer Support     | Professional Services;Engineering |
// | Locality(L)              | Merida                            | Salt Lake,Merida                                   | Salt Lake            | Merida                            |
// | State(ST)                | Yucatan                           | Utah; Yucatan                                      | Utah                 | Yucatan                           |
// | Country(C)               | MX                                | US;MX                                              | US                   | MX                                |
// +--------------------------+-----------------------------------+----------------------------------------------------+----------------------+-----------------------------------+
// As it can be observed, it's expected that the DN values provided through by the venafi_certificate terraform resource
// will be honored and the resulting Certificate will contain them but for the ones which were not provided, the corresponding
// values in the Recommended Settings will be used, as it's happening in this case for Organization (O).
func TestVAASSignedCertWithDN(t *testing.T) {
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.orgUnit1 = "Professional Services"
	data.orgUnit2 = "Engineering"
	data.country = "MX"
	data.state = "Yucatan"
	data.locality = "Merida"

	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(vaasConfigForDnCSRLocalGenerated, vaasProviderCITRestricted, data.cn, data.orgUnit1,
		data.orgUnit2, data.country, data.state, data.locality, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Vaas certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkStandardCertForRecommendedSettings(t, &data, s)
					if err != nil {
						return err
					}
					return nil

				},
			},
		},
	})
}

// This test is to confirm the added support for the Certificate Signing Request DN(Distinguished Name).
// The used TLSPC zone (certificate issuing template) is configured with a set of specific values for the CSR Parameters
// (Organization, Organizational Units, City, State and Country) and with Recommended Settings values being a subset of
// the CSR Parameters values.
// Following a table showing the expected behaviour and the expected values that the resulting certificate will contain
// for the O, OU, L, ST, C parameters
// +==========================+===================================+====================================================+======================+===================================+
// |                          | Terraform venafi_certificate      | CIT configuration                                  | Recommended Settings | Resulting Certificate             |
// +==========================+===================================+====================================================+======================+===================================+
// | Organization(O)          |                                   | Venafi Inc.                                        | Venafi Inc.          |                                   |
// | Organizational Units(OU) | Professional Services;Sales       | Customer Support;Professional Services;Engineering | Customer Support     | *FAIL given Sales is not an       |
// | Locality(L)              | Merida                            | Salt Lake,Merida                                   | Salt Lake            | accepted value by the CIT         |
// | State(ST)                | Yucatan                           | Utah; Yucatan                                      | Utah                 |                                   |
// | Country(C)               | MX                                | US;MX                                              | US                   |                                   |
// +--------------------------+-----------------------------------+----------------------------------------------------+----------------------+-----------------------------------+
// As it can be observed, it's expected that the Request Certificate operation fails given TLSPC will reject it due one
// of the configured Organizational Units by the venafi_certificate terraform resource, specifically "Sales" is not accepted
// by the CIT because the CIT have set Customer Support;Professional Services;Engineering as acceptable values for OU.
func TestVAASSignedCertWithUnacceptableDN(t *testing.T) {
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.orgUnit1 = "Professional Services"
	data.orgUnit2 = "Sales" // This value is not an acceptable value due the OU in the CIT doesn't contain it
	data.country = "MX"
	data.state = "Yucatan"
	data.locality = "Merida"

	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(vaasConfigForDnCSRLocalGenerated, vaasProviderCITRestricted, data.cn, data.orgUnit1,
		data.orgUnit2, data.country, data.state, data.locality, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Vaas certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(fmt.Sprintf(VcertErrorLocalCsrUnacceptableOu, data.orgUnit2)),
			},
		},
	})
}

// This test is to confirm the added support for the Certificate Signing Request DN(Distinguished Name).
// The used TLSPC zone (certificate issuing template) is configured with a set of specific values for the CSR Parameters
// (Organization, Organizational Units, City, State and Country) and with Recommended Settings values being a subset of
// the CSR Parameters values.
// Following a table showing the expected behaviour and the expected values that the resulting certificate will contain
// for the O, OU, L, ST, C parameters
// +==========================+===================================+====================================================+======================+===================================+
// |                          | Terraform venafi_certificate      | CIT configuration                                  | Recommended Settings | Resulting Certificate             |
// +==========================+===================================+====================================================+======================+===================================+
// | Organization(O)          |                                   | Venafi Inc.                                        | Venafi Inc.          | Venafi Inc.                       |
// | Organizational Units(OU) | Professional Services;Engineering | Customer Support;Professional Services;Engineering | Customer Support     | Professional Services;Engineering |
// | Locality(L)              | Merida                            | Salt Lake,Merida                                   | Salt Lake            | Merida                            |
// | State(ST)                | Yucatan                           | Utah; Yucatan                                      | Utah                 | Yucatan                           |
// | Country(C)               | MX                                | US;MX                                              | US                   | MX                                |
// +--------------------------+-----------------------------------+----------------------------------------------------+----------------------+-----------------------------------+
// As it can be observed, it's expected that the DN values provided through by the venafi_certificate terraform resource
// will be honored and the resulting Certificate will contain them but for the ones which were not provided, the corresponding
// values in the Recommended Settings will be used.
func TestVAASSignedCertWithDNServiceGeneratedCSR(t *testing.T) {
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.orgUnit1 = "Professional Services"
	data.orgUnit2 = "Engineering"
	data.country = "MX"
	data.state = "Yucatan"
	data.locality = "Merida"

	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(vaasConfigForDnCSRServiceGenerated, vaasProviderCITRestricted, data.cn, data.orgUnit1,
		data.orgUnit2, data.country, data.state, data.locality, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Vaas certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					err := checkStandardCertForRecommendedSettings(t, &data, s)
					if err != nil {
						return err
					}
					return nil

				},
			},
		},
	})
}

// This test is to confirm the added support for the Certificate Signing Request DN(Distinguished Name).
// The used TLSPC zone (certificate issuing template) is configured with a set of specific values for the CSR Parameters
// (Organization, Organizational Units, City, State and Country) and with Recommended Settings values being a subset of
// the CSR Parameters values.
// Following a table showing the expected behaviour and the expected values that the resulting certificate will contain
// for the O, OU, L, ST, C parameters
// +==========================+===================================+====================================================+======================+===================================+
// |                          | Terraform venafi_certificate      | CIT configuration                                  | Recommended Settings | Resulting Certificate             |
// +==========================+===================================+====================================================+======================+===================================+
// | Organization(O)          |                                   | Venafi Inc.                                        | Venafi Inc.          |                                   |
// | Organizational Units(OU) | Professional Services;Sales       | Customer Support;Professional Services;Engineering | Customer Support     | *FAIL given Sales is not an       |
// | Locality(L)              | Merida                            | Salt Lake,Merida                                   | Salt Lake            | accepted value by the CIT         |
// | State(ST)                | Yucatan                           | Utah; Yucatan                                      | Utah                 |                                   |
// | Country(C)               | MX                                | US;MX                                              | US                   |                                   |
// +--------------------------+-----------------------------------+----------------------------------------------------+----------------------+-----------------------------------+
// As it can be observed, it's expected that the Request Certificate operation fails given TLSPC will reject it due one
// of the configured Organizational Units by the venafi_certificate terraform resource, specifically "Sales" is not accepted
// // by the CIT because the CIT have set Customer Support;Professional Services;Engineering as acceptable values for OU.
func TestVAASSignedCertWithUnacceptableDNServiceGeneratedCSR(t *testing.T) {
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.orgUnit1 = "Professional Services"
	data.orgUnit2 = "Sales" // This value is not an acceptable value due the OU in the CIT doesn't contain it
	data.country = "MX"
	data.state = "Yucatan"
	data.locality = "Merida"

	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 48
	config := fmt.Sprintf(vaasConfigForDnCSRServiceGenerated, vaasProviderCITRestricted, data.cn, data.orgUnit1,
		data.orgUnit2, data.country, data.state, data.locality, data.key_algo, data.private_key_password, data.expiration_window)
	t.Logf("Testing Vaas certificate with config:\n %s", config)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(fmt.Sprintf(VcertErrorServiceCsrUnacceptableOu, "\""+data.orgUnit1+"\" \""+data.orgUnit2+"\"")),
			},
		},
	})
}

func TestVAASSignedCertUpdateRenew(t *testing.T) {
	/*
		This test focuses on the renewal feature. We need to set the expiration window to be the same or greater as the certificate
		duration in order for the renew to take action. ExpectNonEmptyPlan is set true since we will always be able to
		update the certificate on terraform plan re-apply. This is applicable for test purposes only, in a real scenario
		the expiration window should not be too long, thus the terraform plan should be empty after a re-apply (once a
		renew re-apply is done after our plugin detected it should be renewed).

		We have two checks: not_after - not_before >= expiration window [should raise error and exit] and
		now + expiration windows < not_after [should update cert]
		VaaS zone creates certificates with duration of 1 week, so we make expiration_window the same size.
	*/
	t.Parallel()
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.private_key_password = "123xxx"
	data.key_algo = rsa2048
	data.expiration_window = 91 * 24 // 91 days, certificate always will require renewal
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

func TestVAASSignedCertUpdateSetGreaterExpWindow(t *testing.T) {
	/*
		We test to create a certificate on first step that has duration less from zone (without setting valid_days)
		than the expiration_window: It should create a Terraform state with an expiration_window  as same as the cert duration.
		On update, we expect a not empty plan due to the expiration_window being equal to cert duration, and the serial
		to be the same since creation of new resource was not applied.
	*/
	t.Parallel()
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

func TestVAASImportCertificate(t *testing.T) {
	t.Parallel()
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

func TestVAASCsrService(t *testing.T) {
	t.Parallel()
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
