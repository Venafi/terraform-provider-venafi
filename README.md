# terraform-provider-venafi

This is a Terraform provider that is developed with the Venafi VCert library (https://github.com/Venafi/vcert).

## Requirements for Venafi Platform policy

1. Policy should have default template configured

2. Currently vcert (which is used in Venafi issuers) supports only user provided CSR. So it is must be set in the policy.

3. MSCA configuration should have http URI set before the ldap URI in X509 extensions, otherwise NGINX ingress controller can't get the certificate chain from URL and OSCP will not work. Example:

```
X509v3 extensions:
    X509v3 Subject Alternative Name:
    DNS:test-cert-manager1.venqa.venafi.com}}
    X509v3 Subject Key Identifier: }}
    61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E}}
    X509v3 Authority Key Identifier: }}
    keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75}}X509v3 CRL Distribution Points:Full Name:
    URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl}}
    URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint}}{{Authority Information Access: }}
    CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt}}
    CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority}}
```

4.  In the Venafi Platform CA configuration template, set  'Automatically include CN as DNS SAN'  to true.

## Usage
### Install plugin

Get the zip package for your OS from release page and unzip it somewhere in your $PATH

### Create provider
This is a Terraform provider that is developed with the Venafi VCert library (https://github.com/Venafi/vcert)
To use the terraform provider create a `main.tf` file. In here you must first create the provider. This would be done by creating a provider block.

```
provider "venafi" {
    api_key = "<API_KEY>"
    zone    = "<ZONE>"      //optional. Defaults to 'default'
}
```

Provider has the following options:

| field          | type    |description                                                  |
| -------------- | --------|-------------------------------------------------------------|
| `url`          |string   |Platform URL. Example: https://venafi.example.com:5008/vedsdk|
| `zone`         |string   |Platform or Cloud zone or policy. Example: Default|
| `tpp_username` |string   |Platform username. Example: admin|
| `tpp_password` |string   |Platfrom password. Example: secret|
| `api_key`      |string   |Cloud API key. Example: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx|
| `trust_bundle` |string   |Trust bundle for the platfrom in PEM format. You can use file function. Example: ${file("chain.pem")}|
| `dev_mode`    |bool     |Set it to true if you just want to test provider without Platform of Cloud configuration|

If you set the 'api_key', the Venafi Cloud endpoint will be used.  If you set the 'tpp_username' and  'tpp_password', Venafi Platform will be used.

### Import trust chain for the Platform

If Venafi Platform uses an internal (self-signed) certificate, you must get your server root certificate
using open ssl command below and provide it as an option to the 'trust_bundle' parameter. Otherwise, the plugin will fail because of untrusted certificate error.
Use the following command to import the certificate to the chain.pem file.
The main.tf file is already configured to use this file as a trust bundle.

```
echo | openssl s_client -showcerts -servername TPP_ADDRESS -connect TPP_ADDRESS:TPP_PORT | openssl x509 -outform pem -out chain.pem
```

Example:

```
echo | openssl s_client -showcerts -servername venafi.example.com -connect venafi.example.com:5008 | openssl x509 -outform pem -out chain.pem
```

### Creating a Certificate / Private Key pair

Certificate can be created using the `venafi_certificate` resource. This resource only has 1 required field.
- `common_name` (string)

The following optional fields can also be set

| field          | type                                  |
| -------------- | --------------------------------------|
| `algorithm`    | string [RSA or ECDSA]   RSA is default|
| `rsa_bits`     | integer (Used when `algorithm`=RSA)   |
| `ecdsa_curve`  | string (Used when `algorithm`=ECDSA)  |
| `san_dns`      | string array                          |
| `san_email`    | string array                          |
| `san_ip`       | string array                          |
| `key_password` | string                                |

After creation this resource will expose 3 further fields

| field             |type    |
| ----------------- | ------ |
| `private_key_pem` | string |
| `chain`           | string |
| `certificate`     | string |

The following example would output the created private key and csr

```
provider "venafi" {
    ...
}

resource "venafi_certificate" "webserver" {
    common_name = "web.vfidev.com"
    algorithm = "RSA"
    rsa_bits = "2048"
    san_dns = [
        "web01.vfidev.com",
        "web02.vfidev.com"
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

# Development

## Pre-requisites
Go language 1.7 or higher.

## Building

Run `make build` to build the project.

This will create the binary `terraform-provider-venafi`. To have Terraform pick up and run the provider, copy the binary to a location on your `$PATH`.

To run tests export following credentials variables:

`
export TF_VAR_TPPUSER='admin'
export TF_VAR_TPPPASSWORD='secret'
export TF_VAR_CLOUDAPIKEY='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx'
export TF_VAR_TPPURL="https://venafi.example.com:5008/vedsdk"
export TF_VAR_TPPZONE="example\\\\zone"
export TF_VAR_CLOUDZONE="Default"
`

Run `make all` to build and test.


