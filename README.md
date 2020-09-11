![Venafi](Venafi_logo.png)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# Venafi Provider for HashiCorp Terraform

This solution adds certificate enrollment capabilities to [HashiCorp Terraform](https://terraform.io/) by seamlessly integrating with the [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://www.venafi.com/platform/cloud/devops) in a manner that ensures compliance with corporate security policy and provides visibility into certificate issuance enterprise wide.

### Venafi Trust Protection Platform Requirements

Your certificate authority (CA) must be able to issue a certificate in
under one minute. Microsoft Active Directory Certificate Services (ADCS) is a
popular choice. Other CA choices may have slightly different
requirements.

Within Trust Protection Platform, configure these settings. For more
information see the _Venafi Administration Guide_.

- A user account that has an authentication token for the "Venafi Provider
  for HashiCorp Terraform" (ID "hashicorp-terraform-by-venafi") API Application
  as of 20.1 (or scope "certificate:manage" for 19.2 through 19.4) or has been
  granted WebSDK Access (deprecated)
- A Policy folder where the user has the following permissions: View, Read,
  Write, Create.
- Enterprise compliant policies applied to the folder including:

  - Subject DN values for Organizational Unit (OU), Organization (O),
    City/Locality (L), State/Province (ST) and Country (C).
  - CA Template that Trust Protection Platform will use to enroll general
    certificate requests.
  - Management Type not locked or locked to 'Enrollment'.
  - Certificate Signing Request (CSR) Generation unlocked or not locked to
    'Service Generated CSR'.
  - Generate Key/CSR on Application not locked or locked to 'No'.
  - (Recommended) Disable Automatic Renewal set to 'Yes'.
  - (Recommended) Key Bit Strength set to 2048 or higher.
  - (Recommended) Domain Whitelisting policy appropriately assigned.

  **NOTE**: If you are using Microsoft ACDS, the CRL distribution point and
  Authority Information Access (AIA) URIs must start with an HTTP URI
  (non-default configuration). If an LDAP URI appears first in the X509v3
  extensions, some applications will fail, such as NGINX ingress controllers.
  These applications aren't able to retrieve CRL and OCSP information.

#### Trust between Vault and Trust Protection Platform

The Trust Protection Platform REST API (WebSDK) must be secured with a
certificate. Generally, the certificate is issued by a CA that is not publicly
trusted so establishing trust is a critical part of your setup.

Two methods can be used to establish trust. Both require the trust anchor
(root CA certificate) of the WebSDK certificate. If you have administrative
access, you can import the root certificate into the trust store for your
operating system. If you don't have administrative access, or prefer not to
make changes to your system configuration, save the root certificate to a file
in PEM format (e.g. /opt/venafi/bundle.pem) and reference it using the
`trust_bundle_file` parameter whenever you create or update a PKI role in your
Vault.

### Venafi Cloud Requirements

If you are using Venafi Cloud, be sure to set up an issuing template, project,
and any other dependencies that appear in the Venafi Cloud documentation.

- Set up an issuing template to link Venafi Cloud to your CA. To learn more,
  search for "Issuing Templates" in the
  [Venafi Cloud Help system](https://docs.venafi.cloud/help/Default.htm).
- Create a project and zone that identifies the template and other information.
  To learn more, search for "Projects" in the
  [Venafi Cloud Help system](https://docs.venafi.cloud/help/Default.htm).

## Setup

The Venafi Provider for HashiCorp Terraform is an officially verified
integration. As such, releases are published to the
[Terraform Registry](https://registry.terraform.io/providers/Venafi/venafi/latest)
where they are available for `terraform init` to automatically download
whenever the provider is referenced by a configuration file.  No setup
steps are required to use an official release of this provider other than to
download and install Terraform itself.

To use a pre-release or custom built version of this provider, manually install
the plugin binary into
[required directory](https://www.terraform.io/docs/commands/init.html#plugin-installation)
using the prescribed
[subdirectory structure](https://www.terraform.io/docs/configuration/provider-requirements.html#source-addresses)
that must align with how the provider is referenced in the `required_providers`
block of the configuration file.

## Usage

A Terraform module is a container for multiple resources that are used together
and the steps that follow illustrate the resources required to enroll certificates
using the Venafi Provider with HashiCorp Terraform 0.12 (and higher). 

1. Declare that the Venafi Provider is required:

   ```text
   terraform {
     required_providers {
       venafi = {
         source = "venafi/venafi"
         version = "~> 0.10.0"
       }
     }
     required_version = ">= 0.13"
   }
   ```

1. Specify the connection and authentication settings for the `venafi` provider:

   **Trust Protection Platform**:

   ```text
   provider "venafi" {
     url          = "https://tpp.venafi.example"
     trust_bundle = file("/path/to/bundle.pem")
     access_token = "p0WTt3sDPbzm2BDIkoJROQ=="
     zone         = "DevOps\\Terraform"
   }
   ```

   **Venafi Cloud**:

   ```text
   provider "venafi" {
     api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
     zone    = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
   }
   ```

   The `venafi` provider has the following options:

   | Property       | Type   | Description                                                  | Env. Variable |
   | -------------- | ------ | ------------------------------------------------------------ | ------------ |
   | `api_key`      | string | Venafi Cloud API key                                         | VENAFI_API |
   | `access_token` | string | Trust Protection Platform access token for the "hashicorp-terraform-by-venafi" API Application | VENAFI_TOKEN |
   | `tpp_username` | string | [DEPRECATED] Trust Protection Platform WebSDK username, use `access_token` if possible | VENAFI_USER |
   | `tpp_password` | string | [DEPRECATED] Trust Protection Platform WebSDK password, use `access_token` if possible | VENAFI_PASS |
   | `trust_bundle` | string | Text file containing trust anchor certificates in PEM format, generally required for TPP | |
   | `url`          | string | Venafi service URL (e.g. "https://tpp.venafi.example"), generally only applicable to TPP | VENAFI_URL |
   | `zone`         | string | Trust Protection Platform policy folder or Venafi Cloud zone ID (shown in Venafi Cloud UI) | VENAFI_ZONE |
   | `dev_mode`     | bool   | When "true", the provider operates without connecting to Trust Protection Platform or Venafi Cloud | VENAFI_DEVMODE |

   >:pushpin: **NOTE**: The indicated environment variables can be used to specify
   values for provider settings rather than including them in a configuration 
   file. Avoid specifying a value for `api_key` unless you are using Venafi Cloud as
   that variable is used by the provider to decide which Venafi service to use.

1. Create a `venafi_certificate` resource that will generate a new key pair and
   enroll the certificate needed by a "tls_server" application:

   ```text
   resource "venafi_certificate" "tls_server" {
     common_name = "web.venafi.example"
     san_dns = [
       "web01.venafi.example",
       "web02.venafi.example"
     ]
     algorithm = "RSA"
     rsa_bits = "2048"
     key_password = "${var.pk_pass}"
   }
   ```

   The `venafi_certificate` resource has the following options, only
   `common_name` is required:

   | Property            | Type          |  Description                                                                      | Default   |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- | --------- |
   | `common_name`       | string        | Common name of certificate                                                        | `none` |
   | `san_dns`           | string array  | List of DNS names to use as subjects of the certificate                           | `none` |
   | `san_email`         | string array  | List of email addresses to use as subjects of the certificate                     | `none` |
   | `san_ip`            | string array  | List of IP addresses to use as subjects of the certificate                        | `none` |
   | `algorithm`         | string        | Key encryption algorithm. RSA or ECDSA                                            | RSA    |
   | `rsa_bits`          | integer       | Number of bits to use when generating an RSA key. Applies when `algorithm`=RSA    | 2048   |
   | `ecdsa_curve`       | string        | ECDSA curve to use when generating a key. Applies when `algorithm`=ECDSA          | P521   |
   | `key_password`      | string        | Private key password                                                              | `none` |
   | `expiration_window` | integer       | Number of hours before certificate expiry to request a new certificate            | 168    |

   >:pushpin: **NOTE**: The `venafi_certificate` resource handles certificate
   renewals as long as a `terraform apply` is done within the `expiration_window`
   period. Keep in mind that the `expiration_window` in the Terraform
   configuration needs to align with the renewal window of the issuing CA to 
   achieve the desired result.

   After enrollment, the `venafi_certificate` resource will expose the following:

   | Property          | Type   |
   | ----------------- | ------ |
   | `private_key_pem` | string |
   | `chain`           | string |
   | `certificate`     | string |
   | `pkcs12`          | string |

1. For verification purposes, output the certificate, private key, and
   chain in PEM format and as a PKCS#12 keystore (base64 encoded):

   ```text
   output "my_private_key" {
     value = "${venafi_certificate.webserver.private_key_pem}"
     sensitive = true
   }

   output "my_certificate" {
     value = "${venafi_certificate.webserver.certificate}"
   }

   output "my_trust_chain" {
     value = "${venafi_certificate.webserver.chain}"
   }

   output "my_p12_keystore" {
     value = "${venafi_certificate.webserver.pkcs12}"
   }
   ```

1. Execute `terraform init`, `terraform plan`, `terraform apply`, and finally
   `terraform show` from the directory containing the configuration file.
