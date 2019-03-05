# Venafi Provider for HashiCorp Terraform

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>

This solution adds certificate enrollment capabilities to [HashiCorp Terraform](https://www.terraform.io/) by seamlessly integrating with the [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) and [Venafi Cloud](https://pki.venafi.com/venafi-cloud/) in a manner that ensures compliance with corporate security policy and provides visibility into certificate issuance across the enterprise.

This Terraform provider is powered by the Venafi VCert library (https://github.com/Venafi/vcert).

## Requirements for usage with Trust Protection Platform

> Note: The following assume certificates will be enrolled by a Microsoft Active Directory Certificate Services (ADCS) certificate authority. Other CAs will also work with this solution but may have slightly different requirements.

1. The Microsoft CA template appropriate for issuing Vault certificates must be assigned by policy, and should have the "Automatically include CN as DNS SAN" option enabled.

2. The WebSDK user that Vault will be using to authenticate with the Venafi Platform has been granted view, read, write, and create permission to their policy folder.

3. The CRL distribution point and Authority Information Access (AIA) URIs configured for certificates issued by the Microsoft ADCS must start with an HTTP URI (non-default configuration).  If an LDAP URI appears first in the X509v3 extensions, NGINX ingress controllers will fail because they aren't able to retrieve CRL and OCSP information. Example:

```
X509v3 extensions:
    X509v3 Subject Alternative Name: DNS:test-cert-manager1.venqa.venafi.com
    X509v3 Subject Key Identifier: 61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E
    X509v3 Authority Key Identifier: keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75
    X509v3 CRL Distribution Points: Full Name:
        URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl
        URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint
    Authority Information Access:
        CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt
        CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority
```

## Usage

### Download and install the Venafi provider plugin

Go to [releases](https://github.com/Venafi/terraform-provider-venafi/releases) and select the latest package for your operating system. 
Then install by downloading the package to a directory in your $PATH.
You will need to rename plugin binary according terafform plugin naming convention. For example terraform-provider-venafi_v0.6.0+109_linux should become
terraform-provider-venafi_v0.6.0

For more information about installing third party plugins please look into official documentation - https://www.terraform.io/docs/configuration/providers.html#third-party-plugins

### Define the Venafi provider

Create a Terraform configuration file called `main.tf` with a "venafi" provider block like this:

```
provider "venafi" {
    url          = "https://tpp.venafi.example:443/vedsdk"
    tpp_username = "local:admin"
    tpp_password = "password"
    zone         = "DevOps\\Terraform"
}
```

and example for Venafi Cloud

```
provider "venafi" {
    api_key = "<API_KEY>"
    zone    = "<ZONE>"
}
```

The Venafi provider has the following options:

| Property       | Type    | Description                                                                            |
| -------------- | ------- | -------------------------------------------------------------------------------------- |
| `zone`         |string   |Venafi Platform policy folder or Venafi Cloud zone (e.g. "Default")                     |
| `url`          |string   |Venafi URL (e.g. "https://tpp.venafi.example:443/vedsdk")                               |
| `tpp_username` |string   |Venafi Platform WebSDK account username                                                 |
| `tpp_password` |string   |Venafi Platfrom WebSDK account password                                                 |
| `api_key`      |string   |Venafi Cloud API key (e.g. "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEE")                          |
| `trust_bundle` |string   |PEM trust bundle for Venafi Platform server certificate (e.g. "${file("bundle.pem")}" ) |
| `dev_mode`     |bool     |When "true" will test the provider without connecting to Venafi Platform or Venafi Cloud|

> Note: Specifying the 'api_key' indicates the Venafi Cloud will be used so it should not be specified when using Venafi Platform is desired and the 'tpp_username' and 'tpp_password' parameters are specified.

### Establishing Trust between Terraform and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA, therefore establishing trust for that server certificate is a critical part of your configuration.  Ideally this is done by obtaining the root CA certificate in the issuing chain in PEM format and copying that file to your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file whenever in your `main.tf` using the 'trust_bundle' parameter like this:

```
provider "venafi" {
    url          = "https://tpp.venafi.example:443/vedsdk"
    trust_bundle = ${file("/opt/venafi/bundle.pem")}
    tpp_username = "local:admin"
    tpp_password = "password"
    zone         = "DevOps\\Terraform"
}
```

### Creating a Certificate and Private Key pair

Certificates are created using the `venafi_certificate` resource which has only one required property, `common_name` (string). The following options may also be specified:

| Property       | Type                                    |
| -------------- | --------------------------------------- |
| `algorithm`    | string [RSA or ECDSA]   RSA is default  |
| `rsa_bits`     | integer (applies when `algorithm`=RSA)  |
| `ecdsa_curve`  | string (applies when `algorithm`=ECDSA) |
| `san_dns`      | string array                            |
| `san_email`    | string array                            |
| `san_ip`       | string array                            |
| `key_password` | string                                  |

After creation this resource will expose the following:

| Property          | Type   |
| ----------------- | ------ |
| `private_key_pem` | string |
| `chain`           | string |
| `certificate`     | string |

The following example would output a freshly generated private key and enrolled certificate with its trust chain:

```
provider "venafi" {
    ...
}

resource "venafi_certificate" "webserver" {
    common_name = "web.venafi.example"
    algorithm = "RSA"
    rsa_bits = "2048"
    san_dns = [
        "web01.venafi.example",
        "web02.venafi.example"
    ]
    key_password = "${var.pk_pass}"
}

output "cert_certificate" {
    value = "${venafi_certificate.webserver.certificate}"
}

output "cert_chain" {
    value = "${venafi_certificate.webserver.chain}"
}

output "cert_private_key" {
    value = "${venafi_certificate.webserver.private_key_pem}"
}
```

To invoke execute `terraform plan`, then `terraform apply`, and finally `terraform show` from the directory containing your Terraform configuration file (e.g. `main.tf`).

## Development

### Prerequisites

Go language 1.7 or higher.

### Building

Run `make build` to build the project.  This will create a provider binary called `terraform-provider-venafi`.  To have Terraform support the provider simply copy the binary to a location in your $PATH.

Run `make all` to build the project and execute tests.  Tests depend on environment variables which should be exported like this beforehand:

```
export TF_VAR_TPPUSER="local:admin"
export TF_VAR_TPPPASSWORD="password"
export TF_VAR_CLOUDAPIKEY="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEE"
export TF_VAR_TPPURL="https://tpp.venafi.example:443/vedsdk"
export TF_VAR_TPPZONE="DevOps\\\\Terraform"
export TF_VAR_CLOUDZONE="Default"
```
