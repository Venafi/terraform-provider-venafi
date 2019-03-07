package venafi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"strings"
	"testing"
)

func TestDevSignedCert(t *testing.T) {
	t.Log("Testing Dev certificate")
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

					return nil
				},
			},
		},
	})
}

func TestDevSignedCertECDSA(t *testing.T) {
	t.Log("Testing Dev ECDSA certificate")
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

					return nil
				},
			},
		},
	})
}

func TestCloudSignedCert(t *testing.T) {
	t.Log("Testing Cloud certificate")
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

					t.Logf("Testing certificate:\n %s",got)
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

					return nil
				},
			},
		},
	})
}

func TestTPPSignedCert(t *testing.T) {
	t.Log("Testing TPP certificate")
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	key_password := "123xxx"

	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: fmt.Sprintf(`
            variable "TPPUSER" {}
            variable "TPPPASSWORD" {}
            variable "TPPURL" {}
            variable "TPPZONE" {}
			variable "TRUST_BUNDLE" {}
            provider "venafi" {
              alias = "tpp"
              url = "${var.TPPURL}"
              tpp_username = "${var.TPPUSER}"
              tpp_password = "${var.TPPPASSWORD}"
              zone = "${var.TPPZONE}"
              trust_bundle = "${file(var.TRUST_BUNDLE)}"
            }
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
            algorithm = "RSA"
            rsa_bits = "2048"
			key_password = "%s"
          }
          output "cert_certificate_tpp" {
			  value = "${venafi_certificate.tpp_certificate.certificate}"
          }
          output "cert_private_key_tpp" {
            value = "${venafi_certificate.tpp_certificate.private_key_pem}"
          }`, data.cn, data.dns_ns, data.dns_ip, data.dns_email, key_password),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["cert_certificate_tpp"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_1\" is not a string")
					}

					t.Logf("Testing certificate:\n %s",got)
					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE----") {
						return fmt.Errorf("key is missing cert PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing cert: %s", err)
					}
					if expected, got := data.cn, cert.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}
					if expected, got := []string{data.cn, data.dns_ns}, cert.DNSNames; !sameStringSlice(got, expected) {
						return fmt.Errorf("incorrect DNSNames: expected %v, got %v", expected, got)
					}
					t.Log("Checking private key")
					gotPrivateUntyped := s.RootModule().Outputs["cert_private_key_tpp"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"cert_private_key_tpp\" is not a string")
					}

					privatePEM, _ := pem.Decode([]byte(gotPrivate))
					if privatePEM.Type != "RSA PRIVATE KEY" {
						return fmt.Errorf("RSA private key is of the wrong type")
					}

					privPemBytes, err := x509.DecryptPEMBlock(privatePEM, []byte(key_password))
					if err != nil {
						return fmt.Errorf("error decrypting private key with password: %s", err)
					}

					pk, err := x509.ParsePKCS1PrivateKey(privPemBytes)
					if err != nil {
						return fmt.Errorf("error parsing RSA private key: %s", err)
					}

					pkMod := pk.PublicKey.N
					certMod := cert.PublicKey.(*rsa.PublicKey).N
					if pkMod.Cmp(certMod) != 0 {
						return fmt.Errorf("certificate public key modulues %s don't match private key modulus %s", certMod, pkMod)
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
			variable "TRUST_BUNDLE" {}
            provider "venafi" {
              alias = "tpp"
              url = "${var.TPPURL}"
              tpp_username = "${var.TPPUSER}"
              tpp_password = "${var.TPPPASSWORD}"
              zone = "${var.TPPZONE}"
              trust_bundle = "${file(var.TRUST_BUNDLE)}"
            }
			resource "venafi_certificate" "tpp_certificate" {
            provider = "venafi.tpp"
            common_name = "tpp-random.venafi.example.com"
            algorithm = "RSA"
            rsa_bits = "4096"
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

					return nil
				},
			},
		},
	})
}
