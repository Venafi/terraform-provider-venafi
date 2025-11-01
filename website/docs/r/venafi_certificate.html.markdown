---
subcategory: "Certificate Issuance"
layout: "venafi"
page_title: "Venafi: venafi_certificate"
description: |-
  Provides access to TLS key and certificate data in CyberArk Machine Identity Service. This can be used to define a CyberArk certificate.
---

# venafi_certificate

!> We dropped support for RSA PKCS#1 formatted keys for TLS certificates in version 15.0 and also for EC Keys in version 
0.15.4 (you can find out more about this transition in [here](https://github.com/Venafi/vcert/releases/tag/v4.17.0)). 
For backward compatibility during Terraform state refresh please update to version 0.15.5 or above.

Provides access to TLS key and certificate data enrolled using Venafi. This can be used to define a certificate.

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

~>**Note:** Updating `expiration_window` will not trigger another resource to be created by itself, thus won't enroll a 
new certificate. This won't apply if the `expiration_window` constraint allows it, this means, if time to expire of the 
certificate is within the expiration window.

* `common_name` - (Required, string) The common name of the certificate.

* `nickname` - (Optional, string) Use to specify a name for the new certificate object that will be created and placed 
in a policy. Only valid for CyberArk Certificate Manager, Self-Hosted.

* `algorithm` - (Optional, string) Key encryption algorithm, either RSA or ECDSA. Defaults to `RSA`.

* `rsa_bits` - (Optional, integer) Number of bits to use when generating an RSA key. Applies when algorithm is `RSA`. 
Defaults to `2048`.

* `ecsa_curve` - (Optional, string) Elliptic curve to use when generating an ECDSA key pair. Applies when algorithm is 
`ECDSA`. Defaults to `P521`.

* `san_dns` - (Optional, set of strings) List of DNS names to use as alternative subjects of the certificate.

* `san_email` - (Optional, set of strings) List of email addresses to use as alternative subjects of the certificate.

* `san_ip` - (Optional, set of strings) List of IP addresses to use as alternative subjects of the certificate.

* `san_uri` - (Optional, set of strings) List of Uniform Resource Identifiers (URIs) to use as alternative subjects of 
the certificate.

* `key_password` - (Optional, string) The password used to encrypt the private key.

* `custom_fields` - (Optional, map) Collection of Custom Field name-value pairs to assign to the certificate.

* `valid_days` - (Optional, integer) Desired number of days for which the new certificate will be valid.

* `issuer_hint` - (Optional, string) Used with `valid_days` to indicate the target issuer when using CyberArk Certificate Manager, Self-Hosted.
Relevant values are: `DigiCert`, `Entrust`, and `Microsoft`.

* `expiration_window` - (Optional, integer) Number of hours before certificate expiry to request a new certificate. 
Defaults to `168`.

* `csr_origin` - (Optional, string) Whether key-pair generation will be `local` or `service` generated. Default is 
`local`.

* `tags` - (Optional, set of strings) List of Certificate Tags defined in CyberArk Certificate Manager, SaaS.

## Attributes Reference

The following attributes are exported:

* `private_key_pem` - The private key in PEM format.

* `chain` - The trust chain of X509 certificate authority certificates in PEM format concatenated together.

* `certificate` - The X509 certificate in PEM format.

* `pkcs12` - A base64-encoded PKCS#12 keystore secured by the `key_password`. Useful when working with resources like 
[azure key_vault_certificate](https://www.terraform.io/docs/providers/azurerm/r/key_vault_certificate.html).

## Certificate Renewal

The `venafi_certificate` resource handles certificate renewals as long as a `terraform apply` is done within the 
`expiration_window` period. Keep in mind that the `expiration_window` in the Terraform configuration needs to align with 
the renewal window of the issuing CA to achieve the desired result.

## Import

~>**Note:** This operation doesn't support `issuer_hint` among the attributes for importing, neither local generated 
certificate key-pair.

~>**Note:** Don't specify an `expiration_window` within your Terraform file when importing, since will trigger a new 
update on re-applying your configuration unless that's desired. By default, we set a value of `168` hours.

The `venafi_certificate` resource supports the Terraform [import](https://www.terraform.io/docs/cli/import/index.html)
method.

The `import_id` is composed by an `id` which is different for each platform, a comma (,) and the `key-password`.

The `id` for each platform is:

**CyberArk Certificate Manager, Self-Hosted:**

The `nickname` of the certificate, which represents the name of the certificate object in CyberArk Certificate Manager, Self-Hosted. 
Internally we built the `pickup_id` using the `zone` defined at the provider block.

~>**Note:** The certificate object name at CyberArk Certificate Manager, Self-Hosted, usually, should be the same as the `common_name` 
provided as it is considered good practice, but the `nickname` actually could differ from the common name, as there are 
some use cases whenever you want to handle certificates with different nicknames. For example, you could have 
certificates with same common name and different SANs, then, you could manage many certificate resources that share the 
same common name using `for_each` and `count` meta arguments.

**CyberArk Certificate Manager, SaaS:**

The `pickup-id`.

->**Note:** You can learn more about the `pickup-id` and pickup actions for CyberArk Certificate Manager, Self-Hosted, 
[here](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#certificate-retrieval-parameters), and for 
CyberArk Certificate Manager, SaaS, [here](https://github.com/Venafi/vcert/blob/master/README-CLI-CLOUD.md)
```sh
terraform import "venafi_certificate.<resource_name>" "<id>,<key-password>"
```
Example (assuming our resource name is `imported_certificate`):

```hcl
resource "venafi_certificate" "imported_certificate" {}
```

**Trust Protection Platform:**
```sh
terraform import "venafi_certificate.imported_certificate" "tpp.venafi.example,my_key_password"
```

**Venafi Control Plane:**
```sh
terraform import "venafi_certificate.imported_certificate" "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,my_key_password"
```
