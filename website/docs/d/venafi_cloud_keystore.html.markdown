---
subcategory: "Cloud Provisioning"
layout: "venafi"
page_title: "Venafi: venafi_cloud_keystore"
description: |-
  Get information on a Venafi Control Plane (VCP) Cloud Keystore 
---

# Data source: venafi_cloud_keystore

Use this data source to get the `ID` of a cloud keystore in Venafi Control Plane, referenced by its name and parent 
cloud provider ID. You can use `venafi_cloud_provider` data source to obtain the ID of the parent cloud provider.

## Example Usage

```hcl
# Find a cloud keystore with a static cloud provider id
data "venafi_cloud_keystore" "ck_example_by_id" {
  cloud_provider_id = "e48897d0-2762-11ef-8fab-79ac590dd358"
  name = "Cloud Keystore Example"
}

# Find a cloud keystore by using venafi_cloud_provider data source as input
data "venafi_cloud_keystore" "ck_example" {
  cloud_provider_id = data.venafi_cloud_provider.cp_example.id
  name = "Cloud Keystore example"
}
```

## Argument Reference

* `cloud_provider_id` - (Required, string) ID of the cloud provider whom the cloud keystore to look up belongs to.
* `name` - (Required, string) Name of the cloud keystore to look up.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `machine_identities_count` - Number of machine identities provisioned to the cloud keystore.
* `type` - The cloud keystore type. Either `ACM`, `AKV` or `GCM`.
