package venafi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"strings"
	"testing"
)

func TestDevSignedCert(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: fmt.Sprintf(`
            provider "venafi" {
              alias = "dev"
              dev_mode = true
            }
			resource "venafi_certificate" "dev_certificate" {
            provider = "venafi.dev"
            common_name = "dev-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "2048"
            san_dns = [
              "dev-web01-random.example.com",
              "dev-web02-random.example.com"
            ]
            san_ip = [
              "10.1.1.1",
              "192.168.0.1"
            ]
            san_email = [
              "dev@venafi.com",
              "dev2@venafi.com"
            ]
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_dev" {
			  value = "${venafi_certificate.dev_certificate.certificate}"
          }
          output "cert_private_key_dev" {
            value = "${venafi_certificate.dev_certificate.private_key_pem}"
          }
                `),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["cert_certificate_dev"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_1\" is not a string")
					}

					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE----") {
						return fmt.Errorf("key is missing cert PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing cert: %s", err)
					}
					if expected, got := "dev-random.venafi.example.com", cert.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}

					if expected, got := 3, len(cert.DNSNames); got != expected {
						return fmt.Errorf("incorrect number of DNS names: expected %v, got %v", expected, got)
					}
					if expected, got := "dev-web01-random.example.com", cert.DNSNames[0]; got != expected {
						return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
					}
					if expected, got := "dev-web02-random.example.com", cert.DNSNames[1]; got != expected {
						return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
					}

					if expected, got := 2, len(cert.IPAddresses); got != expected {
						return fmt.Errorf("incorrect number of IP addresses: expected %v, got %v", expected, got)
					}
					if expected, got := "10.1.1.1", cert.IPAddresses[0].String(); got != expected {
						return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
					}
					if expected, got := "192.168.0.1", cert.IPAddresses[1].String(); got != expected {
						return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
					}

					if expected, got := 2, len(cert.EmailAddresses); got != expected {
						return fmt.Errorf("incorrect number of email: expected %v, got %v", expected, got)
					}

					if expected, got := "dev@venafi.com", cert.EmailAddresses[0]; got != expected {
						return fmt.Errorf("incorrect email 0: expected %v, got %v", expected, got)
					}
					if expected, got := "dev2@venafi.com", cert.EmailAddresses[1]; got != expected {
						return fmt.Errorf("incorrect email 0: expected %v, got %v", expected, got)
					}

					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_dev"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_dev\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) > 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil

				},
			},
			r.TestStep{
				Config: `
            provider "venafi" {
              alias = "dev"
              dev_mode = true
            }
			resource "venafi_certificate" "dev_certificate" {
            provider = "venafi.dev"
            common_name = "dev-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "4096"
            san_dns = [
              "dev-web01-random.example.com",
              "dev-web02-random.example.com"
            ]
            san_ip = [
              "10.1.1.1",
              "192.168.0.1"
            ]
            san_email = [
              "dev@venafi.com",
              "dev2@venafi.com"
            ]
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_dev" {
			  value = "${venafi_certificate.dev_certificate.certificate}"
          }
          output "cert_private_key_dev" {
            value = "${venafi_certificate.dev_certificate.private_key_pem}"
          }`, Check: func(s *terraform.State) error {
					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_dev"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_dev\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) < 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil
				},
			},
		},
	})
}

func TestDevSignedCertECDSA(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: `
            provider "venafi" {
              alias = "dev"
              dev_mode = true
            }
			resource "venafi_certificate" "dev_certificate" {
            provider = "venafi.dev"
            common_name = "dev-random.venafi.example.com"
            algorithm = "ECDSA"
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_dev_ecdsa" {
			  value = "${venafi_certificate.dev_certificate.certificate}"
          }
          output "cert_private_key_dev_ecdsa" {
            value = "${venafi_certificate.dev_certificate.private_key_pem}"
          }`, Check: func(s *terraform.State) error {
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_dev_ecdsa"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN EC PRIVATE KEY----") {
						return fmt.Errorf("Private key is missing EC key PEM preamble")
					}

					if len(gotPrivate) > 250 {
						return fmt.Errorf("private key PEM looks too long for a ECDSA key (got %v characters)", len(gotPrivate))
					}
					return nil
				},
			},
		},
	})
}

func TestCloudSignedCert(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: fmt.Sprintf(`
            variable "CLOUDURL" {}
            variable "CLOUDAPIKEY" {}
            variable "CLOUDZONE" {}
            provider "venafi" {
              alias = "cloud"
              url = "${var.CLOUDURL}"
              api_key = "${var.CLOUDAPIKEY}"
              zone = "${var.CLOUDZONE}"
            }
			resource "venafi_certificate" "cloud_certificate" {
            provider = "venafi.cloud"
            common_name = "cloud-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "2048"
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_cloud" {
			  value = "${venafi_certificate.cloud_certificate.certificate}"
          }
          output "cert_private_key_cloud" {
            value = "${venafi_certificate.cloud_certificate.private_key_pem}"
          }
                `),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["cert_certificate_cloud"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_1\" is not a string")
					}

					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE----") {
						return fmt.Errorf("key is missing cert PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing cert: %s", err)
					}
					if expected, got := "cloud-random.venafi.example.com", cert.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}

					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_cloud"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_cloud\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) > 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil

				},
			},
			r.TestStep{
				Config: `
            variable "CLOUDURL" {}
            variable "CLOUDAPIKEY" {}
            variable "CLOUDZONE" {}
            provider "venafi" {
              alias = "cloud"
              url = "${var.CLOUDURL}"
              api_key = "${var.CLOUDAPIKEY}"
              zone = "${var.CLOUDZONE}"
            }
			resource "venafi_certificate" "cloud_certificate" {
            provider = "venafi.cloud"
            common_name = "cloud-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "4096"
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_cloud" {
			  value = "${venafi_certificate.cloud_certificate.certificate}"
          }
          output "cert_private_key_cloud" {
            value = "${venafi_certificate.cloud_certificate.private_key_pem}"
          }`, Check: func(s *terraform.State) error {
					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_cloud"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_cloud\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) < 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil
				},
			},
		},
	})
}

func TestTPPSignedCert(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: fmt.Sprintf(`
            variable "TPPUSER" {}
            variable "TPPPASSWORD" {}
            variable "TPPURL" {}
            variable "TPPZONE" {}
            provider "venafi" {
              alias = "tpp"
              url = "${var.TPPURL}"
              tpp_username = "${var.TPPUSER}"
              tpp_password = "${var.TPPPASSWORD}"
              zone = "${var.TPPZONE}"
              trust_bundle = "${file("../chain.pem")}"
            }
			resource "venafi_certificate" "tpp_certificate" {
            provider = "venafi.tpp"
            common_name = "tpp-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "2048"
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_tpp" {
			  value = "${venafi_certificate.tpp_certificate.certificate}"
          }
          output "cert_private_key_tpp" {
            value = "${venafi_certificate.tpp_certificate.private_key_pem}"
          }
                `),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["cert_certificate_tpp"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_1\" is not a string")
					}

					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE----") {
						return fmt.Errorf("key is missing cert PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing cert: %s", err)
					}
					if expected, got := "tpp-random.venafi.example.com", cert.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}

					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_tpp"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_tpp\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) > 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil

				},
			},
			r.TestStep{
				Config: `
            variable "TPPUSER" {}
            variable "TPPPASSWORD" {}
            variable "TPPURL" {}
            variable "TPPZONE" {}
            provider "venafi" {
              alias = "tpp"
              url = "${var.TPPURL}"
              tpp_username = "${var.TPPUSER}"
              tpp_password = "${var.TPPPASSWORD}"
              zone = "${var.TPPZONE}"
              trust_bundle = "${file("../chain.pem")}"
            }
			resource "venafi_certificate" "tpp_certificate" {
            provider = "venafi.tpp"
            common_name = "tpp-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "4096"
            store_pkey = "true"
			key_password = "123xxx"
          }
          output "cert_certificate_tpp" {
			  value = "${venafi_certificate.tpp_certificate.certificate}"
          }
          output "cert_private_key_tpp" {
            value = "${venafi_certificate.tpp_certificate.private_key_pem}"
          }`, Check: func(s *terraform.State) error {
					//Testing private key
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_tpp"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_tpp\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}

					if len(gotPrivate) < 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}
					return nil
				},
			},
		},
	})
}
