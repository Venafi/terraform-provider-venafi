[![Venafi](.github/images/Venafi_logo.png)](https://www.venafi.com/)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi Provider for HashiCorp Terraform

This solution adds certificate enrollment capabilities to [HashiCorp Terraform](https://terraform.io/) by seamlessly integrating with the [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi as a Service](https://www.venafi.com/venaficloud) in a manner that ensures compliance with corporate security policy and provides visibility into certificate issuance enterprise wide.

>:red_car: **Test drive our integration examples today**
>
>Let us show you _step-by-step_ how to add certificates to your _Infrastucture as Code_ automation using Terraform.
> 
>
>Products | Available integration examples...
>:------: | --------
>[<img src="examples/logo_tile_f5.png?raw=true" alt="F5 BIG-IP" width="40" height="40" />](examples/f5_bigip/README.md) | [How to configure secure application delivery using F5 BIG-IP and the Venafi Provider for HashiCorp Terraform](examples/f5_bigip/README.md)
>[<img src="examples/logo_tile_citrix.png?raw=true" alt="Citrix ADC" width="40" height="40" />](examples/citrix_adc/README.md) | [How to configure secure application delivery using Citrix ADC and the Venafi Provider for HashiCorp Terraform](examples/citrix_adc/README.md)
>[<img src="examples/logo_tile_iis.png?raw=true" alt="Microsoft IIS" width="40" height="40" />](examples/microsoft_iis/README.md) | [How to secure and configure Microsoft IIS using the Venafi Provider for HashiCorp Terraform](examples/microsoft_iis/README.md)
>
>**NOTE** If you don't see an example for a product you use, check back later. We're working hard to add more integration examples.

## Requirements

### Venafi Trust Protection Platform

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

#### Trust between Terraform and Trust Protection Platform

The Trust Protection Platform REST API (WebSDK) must be secured with a
certificate. Generally, the certificate is issued by a CA that is not publicly
trusted so establishing trust is a critical part of your setup.

Two methods can be used to establish trust. Both require the trust anchor
(root CA certificate) of the WebSDK certificate. If you have administrative
access, you can import the root certificate into the trust store for your
operating system. If you don't have administrative access, or prefer not to
make changes to your system configuration, save the root certificate to a file
in PEM format (e.g. /opt/venafi/bundle.pem) and include it using the
`trust_bundle` parameter of your Venafi provider.

### Venafi as a Service

If you are using Venafi as a Service, verify the following:

- The Venafi as a Service REST API at [https://api.venafi.cloud](https://api.venafi.cloud/swagger-ui.html)
is accessible from the system where Terraform will run.
- You have successfully registered for a Venafi as a Service account, have been granted at least the
"Resource Owner" role, and know your API key.
- A CA Account and Issuing Template exist and have been configured with:
    - Recommended Settings values for:
        - Organizational Unit (OU)
        - Organization (O)
        - City/Locality (L)
        - State/Province (ST)
        - Country (C)
    - Issuing Rules that:
        - (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        - (Recommended) Restricts the Key Length to 2048 or higher
        - (Recommended) Does not allow Private Key Reuse
- An Application exists where you are among the owners, and you know the Application name.
- An Issuing Template is assigned to the Application, and you know its API Alias.

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
using the Venafi Provider with HashiCorp Terraform 0.13 or higher.  

>:pushpin: **NOTE**: For Terraform 0.12, omit the `required_providers` block and
specify any desired version constraints for the provider in the `provider` block
using the
[older way to manage provider versions](https://www.terraform.io/docs/configuration/providers.html#version-an-older-way-to-manage-provider-versions).

1. Declare that the Venafi Provider is required:

   ```text
   terraform {
     required_providers {
       venafi = {
         source = "venafi/venafi"
         version = "~> 0.13.0"
       }
     }
     required_version = ">= 0.13"
   }
   ```

2. Specify the connection and authentication settings for the `venafi` provider:

   **Trust Protection Platform**:

   ```text
   provider "venafi" {
     url          = "https://tpp.venafi.example"
     trust_bundle = file("/path/to/bundle.pem")
     access_token = "p0WTt3sDPbzm2BDIkoJROQ=="
     zone         = "DevOps\\Terraform"
   }
   ```

   **Venafi as a Service**:

   ```text
   provider "venafi" {
     api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
     zone    = "Business App\\Enterprise CIT"
   }
   ```

   The `venafi` provider has the following options:

   | Property       | Type   | Description                                                  | Env. Variable |
   | -------------- | ------ | ------------------------------------------------------------ | ------------ |
   | `api_key`      | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Venafi as a Service API key                                         | VENAFI_API |
   | `access_token` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Trust Protection Platform access token for the "hashicorp-terraform-by-venafi" API Application | VENAFI_TOKEN |
   | `tpp_username` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible | VENAFI_USER |
   | `tpp_password` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible | VENAFI_PASS |
   | `trust_bundle` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Text file containing trust anchor certificates in PEM format, generally required for Trust Protection Platform | |
   | `url`          | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Venafi service URL (e.g. "https://tpp.venafi.example"), generally only applicable to Trust Protection Platform | VENAFI_URL |
   | `zone`         | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Policy folder for TPP or Application name and Issuing Template API Alias for VaaS (e.g. "Business App\Enterprise CIT") | VENAFI_ZONE |
   | `dev_mode`     | [Boolean](https://www.terraform.io/docs/extend/schemas/schema-types.html#typebool)   | When "true", the provider operates without connecting to TPP or VaaS | VENAFI_DEVMODE |

   >:pushpin: **NOTE**: The indicated environment variables can be used to specify
   values for provider settings rather than including them in a configuration 
   file. Avoid specifying a value for `api_key` unless you are using Venafi as a 
   Service since that variable is used by the provider to decide which Venafi product
   to use.

3. Create a `venafi_certificate` resource that will generate a new key pair and
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

   >:pushpin: **NOTE**: Updating only `expiration_window` will not trigger another resource to be created by itself, thus won't enroll a new certificate. This won't apply if the expiration_window constraint allows it, this means, if time to expire of the certificate is within the expiration window.

   | Property            | Type          |  Description                                                                      | Default   |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- | --------- |
   | `common_name`       | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Common name of certificate                                                        | `none` |
   | `san_dns`           | [List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist) | String array of DNS names to use as alternative subjects of the certificate               | `none` |
   | `san_email`         | [List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist) | String array of email addresses to use as alternative subjects of the certificate         | `none` |
   | `san_ip`            | [List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist) | String array of IP addresses to use as alternative subjects of the certificate            | `none` |
   | `san_uri`           | [List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist) | String array of Uniform Resource Identifiers (URIs) to use as alternative subjects of the certificate            | `none` |
   | `algorithm`         | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Key encryption algorithm (i.e. RSA or ECDSA)                                      | RSA    |
   | `rsa_bits`          | [Integer](https://www.terraform.io/docs/extend/schemas/schema-types.html#typeint) | Number of bits to use when generating an RSA key pair (i.e. 2048 or 4096). Applies when `algorithm`=RSA | 2048   |
   | `ecdsa_curve`       | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | ECDSA curve to use when generating a key pair (i.e. P256, P384, P521). Applies when `algorithm`=ECDSA | P521   |
   | `key_password`      | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Private key password                                                              | `none` |
   | `custom_fields`     | [Map](https://www.terraform.io/docs/extend/schemas/schema-types.html#typemap) | Collection of key-value pairs where the key is the name of the Custom Field in Trust Protection Platform.  For list type Custom Fields, use the \| character to delimit mulitple values.<br/>Example: `custom_fields = { "Number List" = "2\|4\|6" }` | `none` |
   | `valid_days` | [Integer](https://www.terraform.io/docs/extend/schemas/schema-types.html#typeint) | Desired number of days for which the new certificate will be valid | `none` |
   | `issuer_hint` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Used with `valid_days` to indicate the target issuer when using Trust Protection Platform and the CA is DigiCert, Entrust, or Microsoft.<br/>Example: `issuer_hint = "Microsoft"` | `none` |
   | `expiration_window` | [Integer](https://www.terraform.io/docs/extend/schemas/schema-types.html#typeint) | Number of hours before certificate expiry to request a new certificate            | 168    |
   | `csr_origin` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Option to decide whether key-pair generation will be `local` or `service` generated | `local` |

   >:pushpin: **NOTE**: The `venafi_certificate` resource handles certificate
   renewals as long as a `terraform apply` is done within the `expiration_window`
   period. Keep in mind that the `expiration_window` in the Terraform
   configuration needs to align with the renewal window of the issuing CA to 
   achieve the desired result.

   After enrollment, the `venafi_certificate` resource will expose the following:

   | Property          | Type   | Description |
   | ----------------- | ------ | ----------- |
   | `private_key_pem` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Private key in PEM format encrypted using `key_password`, if specified |
   | `chain`           | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Trust chain CA certificate(s) in PEM format concatenated one after the other |
   | `certificate`     | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | End-entity certificate in PEM format |
   | `pkcs12`          | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | Base64-encoded PKCS#12 keystore encrypted using `key_password`, if specified. Useful when working with resources like [azurerm_key_vault_certificate](https://www.terraform.io/docs/providers/azurerm/r/key_vault_certificate.html). Base64 decode to obtain file bytes. |

4. For verification purposes, output the certificate, private key, and
   chain in PEM format and as a PKCS#12 keystore (base64-encoded):

   ```text
   output "my_private_key" {
     value = venafi_certificate.tls_server.private_key_pem
     sensitive = true
   }

   output "my_certificate" {
     value = venafi_certificate.tls_server.certificate
   }

   output "my_trust_chain" {
     value = venafi_certificate.tls_server.chain
   }

   output "my_p12_keystore" {
     value = venafi_certificate.tls_server.pkcs12
   }
   ```

5. Execute `terraform init`, `terraform plan`, `terraform apply`, and finally
   `terraform show` from the directory containing the configuration file.

### Importing

>:pushpin: **NOTE**: Don't specify an `expiration_window` within your Terraform file when importing, since will trigger a new update on re-applying your configuration unless that's desired. By default we set a value of `168` hours.

>:pushpin: **NOTE**: This operation doesn't support `issuer_hint` among the attributes for importing, neither local generated certificate key-pair.

The `venafi_certificate` resource supports the Terraform [import](https://www.terraform.io/docs/cli/import/index.html)
method.

The `import_id` is composed by an `id` which is different for each platform, a comma (,) and the `key-password`.

The `id` for each platform is:

**TPP:**

The `common name` of the certificate, internally we built the `pickup_id` using the `zone` defined at the provider block.

**VaaS:**

The `pickup-id`.

>:pushpin: **NOTE**: You can learn more about the `pickup-id` and pickup actions for TPP, [here](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#certificate-retrieval-parameters), and for Vaas, [here](https://github.com/Venafi/vcert/blob/master/README-CLI-CLOUD.md)
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

## Certificate Policy Management

1. Declare that the Venafi Provider and specify the connection and
   authentication settings as described in the previous section.

   >:pushpin: **NOTE**: For Trust Protection Platform, the 
   `access_token` assigned to the `venafi` provider must have the
   *configuration:manage* scope in order to apply certificate policy.

2. Create a `venafi_policy` resource that will create or update the
   certificate policy for a Venafi zone:

   ```text
   resource "venafi_policy" "tls_server_certificates" {
     zone = "My Business App\\Server Certificates"
     policy_specification = file("/path/to/tls_server_cert_policy.json")
   }
   ```

   The `venafi_policy` resource has the following options, all of which
   are required when setting policy:

   | Property            | Type          |  Description                                                                      | Default   |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- | --------- |
   | `zone` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | The *Trust Protection Plaform* policy folder or *Venafi as a Service* application and issuing template | `none` |
   | `policy_specification` | [String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | The JSON-formatted certificate policy specification as documented [here](https://github.com/Venafi/vcert/blob/master/README-POLICY-SPEC.md).  Typically read from a file using the [file](https://www.terraform.io/docs/language/functions/file.html) function. Use the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#parameters-for-viewing-certificate-policy) to generate a policy specification template to get started (i.e. `vcert getpolicy --starter`) | `none` |

   >:pushpin: **NOTE**: The `venafi_policy` resource supports the
   `terraform import` method.  When used, the `zone` and 
   `policy_specification` options are not required since the zone
   is a required parameter of the import method and the policy
   specification is populated from the existing infrastructure.
   Policy that is successfully imported is also output to a file
   named after the zone that was specified.  The 
   *certificate:manage* scope is require to import policy from TPP.

## SSH Certificate Management

1. Declare the Venafi provider and specify the connection and authentication settings as described in the previous sections.

   >:pushpin: **NOTE**: For Trust Protection Platform, the access_token assigned to the Venafi provider must have the ssh:manage scope in order to create SSH certificates.

   **Trust Protection Platform**:

    ```
    provider "venafi" {
      url          = "https://tpp.venafi.example"
      trust_bundle = file("/path/to/bundle.pem")
      access_token = "p0WTt3sDPbzm2BDIkoJROQ=="
    }
    ```

2. Create a resource `venafi_ssh_certificate` that will generate a new key pair and
   enroll the ssh certificate needed by a remote host:

   ```
   resource "venafi_ssh_certificate" "remote-host" {
     key_id = "my_remote"
     template = "devops-terraform"
     public_key_method = "service"
     source_address = ["test.com"]
     key_passphrase = "abcd"
     extension = ["login@github.com:alice@github.com"]
     valid_hours = 4
   }
   ```

   The `venafi_ssh_certificate` resource has the following options, which only `key_id` and `template` are required:

   | Property            | Type          |  Description                                                                      | Default   |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- | --------- |
   |`key_id`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) |The identifier of the requested certificate|`none`|
   |`template`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring)|The certificate issuing template|`none`|
   |`key_passphrase`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring)|Passphrase for encrypting the private key|`none`|
   |`folder`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) |The DN of the policy folder where the certificate object will be created. It will overwrite the default folder set at the template |`none`|
   |`force_command`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring)|The requested force command|`none`|
   |`key_size`|[Int](https://www.terraform.io/docs/extend/schemas/schema-types.html#typeint)|The key size bits, they will be used for creating keypair|`3072`|
   |`windows`|[Bool](https://www.terraform.io/docs/extend/schemas/schema-types.html#typebool)|Output certificate and key files in Windows format (i.e. with \r\n line endings) instead of Unix format (i.e. \n line endings).|`false`|
   |`valid_hours`|[Int](https://www.terraform.io/docs/extend/schemas/schema-types.html#typeint)|How much time the requester wants to have the certificate valid, the format is hours|`none`|
   |`object_name`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) |The friendly name for the certificate object. If not specified, the value of the `key_id` is used.|`none`|
   |`public_key`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring)|The path of the public key that will be used to generate the certificate if `public_key_method` set to `file`|`none`|
   |`public_key_method`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) | If the public key will be: `local` or `service` generated or `file` provided|`local`|
   |`principal` |[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|**[DEPRECATED]** This will be removed in the future. Use `principals` instead. The requested principals|`none`|
   |`principals`|[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|The requested principals|`none`|
   |`source_address`|[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|The requested source addresses as list of IP/CIDR|`none`|
   |`destination_address`|[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|The address (FQDN/hostname/IP/CIDR) of the destination host where the certificate will be used for authentication. Applicable for client certificates and is used for reporting/auditing only.|`none`|
   |`extension`|[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|The requested certificate extensions|`none`|

3. Create a resource `venafi_ssh_config` that will hold configuration needed by a remote host:

   ```
   resource "venafi_ssh_config" "cit" {
     template = "devops-terraform-cit"
   }
   ```   

   The `venafi_ssh_config` resource has the following option, which is required when obtaining configuration from the template:

   | Property            | Type          |  Description                                                                      | Default   |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- | --------- |
   |`template`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring)|The certificate issuing template|`none`|

    In addition, the following attributes are exported:

   | Property            | Type          |  Description                                                                      |
   | ------------------- | ------------- | --------------------------------------------------------------------------------- |
   |`ca_public_key`|[String](https://www.terraform.io/docs/extend/schemas/schema-types.html#typestring) |The template's CA PublicKey|
   |`principals`|[List](https://www.terraform.io/docs/extend/schemas/schema-types.html#typelist)|The requested principals|



## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Mozilla Public License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
