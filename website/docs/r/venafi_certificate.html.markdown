---
layout: "venafi"
page_title: "Venafi: venafi_certificate"
sidebar_current: "docs-venafi-resource-venafi-certificate"
description: |-
  Provides access to TLS key and certificate data in Venafi. This can be used to define a Venafi certificate.
---

# venafi_certificate

Provides access to TLS key and certificate data enrolled using Venafi. This can be used to define a
certificate.

## Example Usage

```hcl
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
```

## Argument Reference

The following arguments are supported:

* `common_name` - (Required, string) The common name of the certificate.

* `algorithm` - (Optional, string) Key encryption algorithm, either RSA or ECDSA.
  Defaults to "RSA".

* `rsa_bits` - (Optional, integer) Number of bits to use when generating an RSA key.
  Applies when algorithm=RSA.  Defaults to 2048.

* `ecsa_curve` - (Optional, string) Elliptic curve to use when generating an ECDSA
  key pair.  Applies when algorithm=ECDSA.  Defaults to "P521".

* `san_dns` - (Optional, set of strings) List of DNS names to use as alternative
  subjects of the certificate.

* `san_email` - (Optional, set of strings) List of email addresses to use as
  alternative subjects of the certificate.

* `san_ip` - (Optional, set of strings) List of IP addresses to use as alternative
  subjects of the certificate.

* `key_password` - (Optional, string) The password used to encrypt the private key.

* `expiration_window` - (Optional, integer) Number of hours before certificate expiry
  to request a new certificate.

## Attributes Reference

The following attributes are exported:

* `private_key_pem` - The private key in PEM format.

* `chain` - The trust chain of X509 certificate authority certificates in PEM format
  concatenated together.

* `certificate` - The X509 certificate in PEM format.

## Certificate Renewal

The `venafi_certificate` resource handles certificate renewals as long as a terraform apply is done within the `expiration_window` period. Keep in mind that this expiration window in Terraform needs to match the renewal window set within your CA/TPP.
