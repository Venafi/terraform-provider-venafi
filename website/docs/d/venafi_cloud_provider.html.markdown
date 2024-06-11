---
subcategory: "Cloud Provisioning"
layout: "venafi"
page_title: "Venafi: venafi_cloud_provider"
description: |-
  Get information on a Venafi Control Plane (VCP) Cloud Provider 
---

# Data Source: venafi_cloud_provider

Use this data source to get the `ID` of a cloud provider in Venafi Control Plane, referenced by its name.

## Example Usage

```hcl
# Find a cloud provider
data "venafi_cloud_provider" "cp_example" {
  name = "Cloud Provider Example"
}
```

## Argument Reference

* `name` - (Required, string) Name of the Cloud Provider to look up.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `keystores_count` - Number of Cloud Keystores configured with the Cloud Provider
* `status` - The status of the Cloud Provider. Either `VALIDATED` or `NOT_VALIDATED`.
* `status_details` - The details of the Cloud Provider status. If the status is `VALIDATED`, this value will be empty.
* `type` - The Cloud Provider type. Either `AWS`, `AZURE` or `GCP`
