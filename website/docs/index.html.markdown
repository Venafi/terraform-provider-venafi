---
layout: "venafi"
page_title: "Provider: Venafi"
sidebar_current: "docs-venafi-index"
description: |-
  Venafi is the enterprise platform for Machine Identity Protection. The Venafi provider streamlines the process of 
  acquiring SSL/TLS keys and certificates from Venafi services giving assurance of compliance with Information Security 
  policies. It provides resources that allow private keys and certificates to be created as part of a Terraform deployment.
---

# Venafi Provider

!> We dropped support for RSA PKCS#1 formatted keys for TLS certificates in version 15.0 and also for EC Keys in version
0.15.4 (you can find out more about this transition in [here](https://github.com/Venafi/vcert/releases/tag/v4.17.0)).
For backward compatibility during Terraform state refresh please update to version 0.15.5 or above.

!> As a part for upgrading our provider to SDK version 2, we dropped support for Terraform version 0.11 and below.

~> With the introduction of version [0.18.0](https://registry.terraform.io/providers/Venafi/venafi/0.18.0) the Venafi 
Terraform provider now incorporates a new feature related to certificate retirement. When an infrastructure is 
decommissioned, the associated certificate will be automatically retired from the Venafi Platform (TLSPDC and VCP).

[Venafi](https://www.venafi.com) is the enterprise platform for Machine Identity Protection. The Venafi provider 
streamlines the process of acquiring SSL/TLS keys and certificates from Venafi services giving assurance of compliance 
with Information Security policies. It provides resources that allow private keys and certificates to be created as 
part of a Terraform deployment.

Use the navigation to the left to read about the available resources.

## Example Usage for Venafi Control Plane
You can sign up for a Venafi Control Plane account by visiting https://vaas.venafi.com/. Once registered, find your API 
key by clicking your name in the top right of the web interface.  You will also need to specify the `zone` to use when 
requesting certificates. Zones define the machine identity policy that will be applied to certificate requests and the 
certificate authority that will issue certificates. The zone is formed by combining the Application Name and Issuing 
Template API Alias (e.g. "Business App\Enterprise CIT").

### US tenants

```hcl
# Configure the Venafi provider. US api url is set by default
provider "venafi" {
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

### EU tenants

```hcl
# Configure the Venafi provider with EU api url
provider "venafi" {
  url     = "https://api.venafi.eu"
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

### AU tenants

```hcl
# Configure the Venafi provider with AU api url
provider "venafi" {
  url     = "https://api.au.venafi.cloud"
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

### UK tenants

```hcl
# Configure the Venafi provider with UK api url
provider "venafi" {
  url     = "https://api.uk.venafi.cloud"
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

### SG tenants

```hcl
# Configure the Venafi provider with SG api url
provider "venafi" {
  url     = "https://api.sg.venafi.cloud"
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

### CA tenants

```hcl
# Configure the Venafi provider with CA api url
provider "venafi" {
  url     = "https://api.ca.venafi.cloud"
  api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

## Example Usage for Venafi Trust Protection Platform

Your Venafi administrator can provide you with the URL for the Trust Protection Platform REST API and grant you 
permission to use it.  At the same time they'll provide you with the Distinguished Name of a policy folder to specify 
for the `zone`. Policy folders define the machine identity policy applied  to certificate requests and the certificate 
authority that will issue certificates. You may also need to ask them for a root CA certificate for your `trust_bundle` 
if the Venafi Platform URL is secured by a certificate your Terraform computer does not already trust.

Obtain the required `access_token` for Trust Protection Platform using the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#obtaining-an-authorization-token)
(`getcred action` with `--client-id "hashicorp-terraform-by-venafi"` and `--scope "certificate:manage"`) or the 
Platform's Authorize REST API method. The *configuration:manage* scope is required to set certificate policy using the 
`venafi_policy` resource.

```hcl
# Configure the Venafi provider
provider "venafi" {
  url          = "https://tpp.venafi.example"
  trust_bundle = "${file("/opt/venafi/bundle.pem")}"
  access_token = "p0WTt3sDPbzm2BDIkoJROQ=="
  zone         = "DevOps\\Terraform"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
  # ...
}
```

## Argument Reference

The following arguments are supported:

* `access_token` - (Optional, string) Authentication token for the 'hashicorp-terraform-by-venafi' API Application. 
Applies only to Venafi Trust Protection Platform.
* `api_key` - (Optional, string) REST API key for authentication. Applies only to Venafi Control Plane.
* `client_id` - (Optional, string) ID of the application that will request a token. Not necessary when `access_token`
  provided. If not provided, defaults to `hashicorp-terraform-by-venafi`.
* `dev_mode` - (Optional, boolean) When "true" will test the provider without connecting to Venafi Platform or Venafi
  Control Plane.
* `external_jwt` - (Optional, string) JWT of the Identity Provider associated to a service account for authentication. 
Applies only to Venafi Control Plane. 
* `p12_cert_filename` - (Optional, string) Filename of PKCS#12 keystore containing a client certificate, private key,
  and chain certificates to authenticate to Venafi Trust Protection Platform.
* `p12_cert_password` - (Optional, string) Password for the PKCS#12 keystore declared in `p12_cert_filename`. Applies 
only to Venafi Trust Protection Platform.
* `skip_retirement` - (Optional, boolean) If it's specified with value `true` then the certificate retirement on the
  related Venafi Platform (TLSPDC or TLSPC) will be skipped. A value of `false` is equivalent to omit this argument.
* `token_url` - (Optional, string) - URL to request access tokens for Venafi Control Plane.
* `tpp_password` **[DEPRECATED]** - (Optional, string) WebSDK account password for authentication (applies only to
  Venafi Platform).
* `tpp_username` **[DEPRECATED]** - (Optional, string) WebSDK account username for authentication (applies only to 
Venafi Platform).
* `trust_bundle` - (Optional, string) PEM trust bundle for Venafi Platform server certificate (e.g. "${file("bundle.pem")}").
* `url` - (Optional, string) Venafi URL (e.g. "https://tpp.venafi.example").
* `zone` - (**Required**, string) Application Name and Issuing Template API Alias (e.g. "Business App\Enterprise CIT")
  for Venafi Control Plane or policy folder for Venafi Trust Protection Platform.

## Environment Variables

The following environment variables can also be used to specify provider
argument values:

* `VENAFI_API` - for `api_key` argument
* `VENAFI_CLIENT_ID` - for `client_id` argument
* `VENAFI_DEVMODE` - for `dev_mode` argument
* `VENAFI_EXTERNAL_JWT` - for `external_jwt` argument
* `VENAFI_PASS` - for `tpp_password` argument
* `VENAFI_P12_CERTIFICATE` - for `p12_cert` argument
* `VENAFI_P12_PASSWORD` - for `p12_password` argument
* `VENAFI_SKIP_RETIREMENT` - for `skip_retirement` argument
* `VENAFI_TOKEN` - for `access_token` argument
* `VENAFI_TOKEN_URL` - for `token_url` argument
* `VENAFI_URL` - for `url` argument
* `VENAFI_USER` - for `tpp_username` argument
* `VENAFI_ZONE` - for `zone` argument
