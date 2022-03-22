---
layout: "venafi"
page_title: "Provider: Venafi"
sidebar_current: "docs-venafi-index"
description: |-
  Venafi is the enterprise platform for Machine Identity Protection. The Venafi provider streamlines the process of acquiring SSL/TLS keys and certificates from Venafi services giving assurance of compliance with Information Security policies.  It provides resources that allow private keys and certficates to be created as part of a Terraform deployment.
---

# Venafi Provider

[Venafi](https://www.venafi.com) is the enterprise platform for Machine Identity
Protection. The Venafi provider streamlines the process of acquiring SSL/TLS
keys and certificates from Venafi services giving assurance of compliance with
Information Security policies.  It provides resources that allow private keys
and certficates to be created as part of a Terraform deployment.

Use the navigation to the left to read about the available resources.

## Example Usage for Venafi as a Service

You can sign up for a Venafi as a Service account by visiting https://vaas.venafi.com/.
Once registered, find your API key by clicking your name in the top right of the web interface.  You 
will also need to specify the `zone` to use when requesting certificates. Zones define the machine 
identity policy that will be applied to certificate requests and the certificate authority that will 
issue certificates. The zone is formed by combining the Application Name and Issuing Template API Alias 
(e.g. "Business App\Enterprise CIT").

```hcl
# Configure the Venafi provider
provider "venafi" {
    api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    zone    = "Business App\\Enterprise CIT"
}

# Generate a key pair and request a certificate
resource "venafi_certificate" "webserver" {
    # ...
}
```

## Example Usage for Venafi Trust Protection Platform

Your Venafi administrator can provide you with the URL for the Trust Protection Platform REST API and
grant you permission to use it.  At the same time they'll provide you with the Distinguished Name of a
policy folder to specify for the `zone`.  Policy folders define the machine identity policy applied
to certificate requests and the certificate authority that will issue certificates. You may also need
to ask them for a root CA certificate for your `trust_bundle` if the Venafi Platform URL is secured by
a certificate your Terraform computer does not already trust.

Obtain the required `access_token` for Trust Protection Platform using the 
[VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#obtaining-an-authorization-token)
(`getcred action` with `--client-id "hashicorp-terraform-by-venafi"` and `--scope "certificate:manage"`) or
the Platform's Authorize REST API method.  The *configuration:manage* scope is required to set certificate
policy using the `venafi_policy` resource.

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

* `zone` - (Required, string) Application Name and Issuing 
Template API Alias (e.g. "Business App\Enterprise CIT") for Venafi as a Service or policy folder for Venafi Platform.

* `url` - (Optional, string) Venafi URL (e.g. "https://tpp.venafi.example").

* `access_token` - (Optional, string) authentication token for the 'hashicorp-terraform-by-venafi' API Application (applies only to Venafi Platform).

* `api_key` - (Optional, string) REST API key for authentication (applies only to Venafi as a Service).

* `tpp_username` [DEPRECATED] - (Optional, string) WebSDK account username for authentication (applies only to Venafi Platform).

* `tpp_password` [DEPRECATED] - (Optional, string) WebSDK account password for authentication (applies only to Venafi Platform).

* `trust_bundle` - (Optional, string) PEM trust bundle for Venafi Platform server certificate (e.g. "${file("bundle.pem")}" ).

* `dev_mode` - (Optional, boolean) When "true" will test the provider without connecting to Venafi Platform or Venafi as a Service.

## Environment Variables

The following environment variables can also be used to specify provider 
argument values:

* VENAFI_ZONE
* VENAFI_URL
* VENAFI_TOKEN
* VENAFI_API
* VENAFI_USER
* VENAFI_PASS
* VENAFI_DEVMODE
