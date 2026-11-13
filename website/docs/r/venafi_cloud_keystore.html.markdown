---
subcategory: "Cloud Provisioning"
layout: "venafi"
page_title: "Venafi: venafi_cloud_keystore"
description: |-
  Manages a Cloud Keystore in CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)
---

# Resource: venafi_cloud_keystore

Manages a Cloud Keystore: an AWS Certificate Manager (ACM) region, an Azure Key Vault (AKV) or a Google Cloud Certificate
Manager (GCM) location, reached through a [venafi_cloud_provider](./venafi_cloud_provider.html.markdown). The Cloud Provider must be validated
first; reference a [venafi_cloud_provider_validation](./venafi_cloud_provider_validation.html.markdown) in
`cloud_provider_id` so that the keystore is only created once it is. Certificates
are provisioned to a Cloud Keystore with the
[venafi_cloud_keystore_installation](./venafi_cloud_keystore_installation.html.markdown) resource.

## Example Usage

```hcl
# ACM, on CyberArk Certificate Manager, SaaS, which requires an owning team
resource "venafi_cloud_keystore" "acm_example" {
  name              = "us-east-1"
  type              = "ACM"
  cloud_provider_id = venafi_cloud_provider_validation.aws_example.cloud_provider_id
  team              = "Cloud Admins"

  acm {
    region = "us-east-1"
  }

  discovery_schedule           = "00 03 * * *"
  include_expired_certificates = false
}

# AKV
resource "venafi_cloud_keystore" "akv_example" {
  name              = "prod-vault"
  type              = "AKV"
  cloud_provider_id = venafi_cloud_provider_validation.azure_example.cloud_provider_id

  akv {
    key_vault_name = "prod-vault"
  }
}

# GCM
resource "venafi_cloud_keystore" "gcm_example" {
  name              = "global"
  type              = "GCM"
  cloud_provider_id = venafi_cloud_provider_validation.gcp_example.cloud_provider_id

  gcm {
    project_id = "my-project"
    location   = "global"
  }
}
```

## Argument Reference

* `name` - (Required, string) Name of the Cloud Keystore.
* `type` - (Required, string) Type of the Cloud Keystore: `ACM`, `AKV` or `GCM`. Changing it creates a new Cloud Keystore.
* `cloud_provider_id` - (Required, string) ID of the Cloud Provider the keystore belongs to. Changing it creates a new Cloud Keystore.
* `team` - (Optional, string) Name or ID of the team that owns the Cloud Keystore. Required for CyberArk Certificate Manager, SaaS. Palo Alto Networks Next-Gen Trust Security (NGTS) only accepts a team ID.
* `acm` - (Optional, block) Configuration of an ACM keystore. Required when `type` is `ACM`, and not allowed otherwise. Changing it creates a new Cloud Keystore.
  * `region` - (Required, string) AWS region of the certificate manager.
  * `account_id` - (Optional, string) AWS account ID, when it differs from the Cloud Provider's.
* `akv` - (Optional, block) Configuration of an AKV keystore. Required when `type` is `AKV`, and not allowed otherwise. Changing it creates a new Cloud Keystore.
  * `key_vault_name` - (Required, string) Name of the Azure key vault.
* `gcm` - (Optional, block) Configuration of a GCM keystore. Required when `type` is `GCM`, and not allowed otherwise. Changing it creates a new Cloud Keystore.
  * `project_id` - (Required, string) GCP project ID.
  * `location` - (Required, string) GCP location of the certificate manager, for example `global`.
* `discovery_schedule` - (Optional, string) Crontab expression for scheduled certificate discovery, for example `00 03 * * *` runs every day at 3 AM. Removing it removes the schedule.
* `include_expired_certificates` - (Optional, bool) Whether discovery includes expired certificates. Defaults to the platform's setting.
* `include_revoked_certificates` - (Optional, bool) Whether discovery includes revoked certificates. Defaults to the platform's setting.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - The ID of the Cloud Keystore.
* `cloud_provider_name` - Name of the Cloud Provider the keystore belongs to.
* `machine_identities_count` - Number of certificates installed in or discovered on the keystore.

## Import

Using `terraform import`, import a Cloud Keystore using its ID. For example:

```console
terraform import venafi_cloud_keystore.example e48897d0-2762-11ef-198k-79ac590dd358
```

The `team` is not read back from the platform.
