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
    san_dns = [
        "web01.venafi.example",
        "web02.venafi.example"
    ]
    algorithm = "RSA"
    rsa_bits = "2048"
    key_password = "${var.pk_pass}"
    custom_fields = {
        "Cost Center" = "AB1234",
        "Environment" = "UAT|Staging"
    }
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

* `custom_fields` - (Optional, map) Collection of Custom Field name-value pairs to
  assign to the certificate.

* `valid_days` - (Optional, integer) Desired number of days for which the new
  certificate will be valid.

* `issuer_hint` - (Optional, string) Used with valid_days to indicate the target
  issuer when using Trust Protection Platform.  Relevant values are: "DigiCert",
  "Entrust", and "Microsoft".

* `expiration_window` - (Optional, integer) Number of hours before certificate expiry
  to request a new certificate.

* `csr_origin` - (Optional, string) Whether key-pair generation will be `local` or `service` generated. Default is `local`.

## Attributes Reference

The following attributes are exported:

* `private_key_pem` - The private key in PEM format.

* `chain` - The trust chain of X509 certificate authority certificates in PEM format
  concatenated together.

* `certificate` - The X509 certificate in PEM format.

* `pkcs12` - A base64-encoded PKCS#12 keystore secured by the `key_password`.
  Useful when working with resources like 
  [azurerm_key_vault_certificate](https://www.terraform.io/docs/providers/azurerm/r/key_vault_certificate.html).

## Certificate Renewal

The `venafi_certificate` resource handles certificate renewals as long as a
`terraform apply` is done within the `expiration_window` period. Keep in mind that the
`expiration_window` in the Terraform configuration needs to align with the renewal
window of the issuing CA to achieve the desired result.

## Import

The `venafi_certificate` resource supports the Terraform [import](https://www.terraform.io/docs/cli/import/index.html)
method. 

The `import_id` is composed by an `id` which is different for each platform, a comma (,) and the `key-password`.

The `id` for each platform is:

**TPP:**

The `common name` of the certificate, internally we built the `pickup_id` using the `zone` defined at the provider block.

**VaaS:**

The `pickup-id`.

->**Note:** You can learn more about the `pickup-id` and pickup actions for TPP, [here](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#certificate-retrieval-parameters), and for Vaas, [here](https://github.com/Venafi/vcert/blob/master/README-CLI-CLOUD.md)
```sh
terraform import "venafi_certificate.<resource_name>" "<id>,<key-password>"
```
Example (assuming our resource name is `imported_certificate`):

```hcl
resource "venafi_certificate" "imported_certificate" {}
```

**TPP:**
```sh
terraform import "venafi_certificate.imported_certificate" "tpp.venafi.example,my_key_password"
```

**VaaS:**
```sh
terraform import "venafi_certificate.imported_certificate" "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,my_key_password"
```

