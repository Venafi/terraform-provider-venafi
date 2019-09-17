---
layout: "venafi"
page_title: "Provider: Venafi"
sidebar_current: "docs-venafi-index"
description: |-
  Venafi is the enterprise platform for Machine Identity Protection. The Venafi provider streamlines the process of acquiring SSL/TLS keys and certificates from Venafi services giving assurance of compliance with Information Security policies.  It provides resources that allow private keys and certficates to be created as part of a Terraform deployment.

# Venafi Provider

[Venafi](https://www.venafi.com) is the enterprise platform for Machine Identity
Protection. The Venafi provider streamlines the process of acquiring SSL/TLS
keys and certificates from Venafi services giving assurance of compliance with
Information Security policies.  It provides resources that allow private keys
and certficates to be created as part of a Terraform deployment.

Use the navigation to the left to read about the available resources.

## Example Usage

```hcl
# Configure the Venafi provider (Trust Protection Platform)
provider "venafi" {
    url          = "https://tpp.venafi.example:443/vedsdk"
    trust_bundle = "${file("/opt/venafi/bundle.pem")}"
    tpp_username = "local:terraform"
    tpp_password = "password"
    zone         = "DevOps\\Terraform"
}

# Generate a key pair and request a certificate
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

# Output the end-entity certificate
output "cert_certificate" {
    value = "${venafi_certificate.webserver.certificate}"
}

# Output chain CA certificates
output "cert_chain" {
    value = "${venafi_certificate.webserver.chain}"
}

# Output the private key
output "cert_private_key" {
    value = "${venafi_certificate.webserver.private_key_pem}"
    sensitive   = true
}
```

## Argument Reference

The following arguments are supported:

* `zone` - (Optional, string) The policy folder for Venafi Platform or zone for Venafi Cloud (e.g. "Default").

* `url` - (Optional, string) Venafi URL (e.g. "https://tpp.venafi.example:443/vedsdk").

* `tpp_username` - (Optional, string) WebSDK account username for authentication (applies only to Venafi Platform).

* `tpp_password` - (Optional, string) WebSDK account password for authentication (applies only to Venafi Platform).

* `api_key` - (Optional, string) REST API key for authentication (applies only to Venafi Cloud).

* `trust_bundle` - (Optional, string) PEM trust bundle for Venafi Platform server certificate (e.g. "${file("bundle.pem")}" ).

* `dev_mode` - (Optional, boolean) When "true" will test the provider without connecting to Venafi Platform or Venafi Cloud.

## Environment Variables

The following environment variables can also be used to specify provider 
argument values:

* VENAFI_ZONE
* VENAFI_URL
* VENAFI_USER
* VENAFI_PASS
* VENAFI_API
* VENAFI_DEVMODE
