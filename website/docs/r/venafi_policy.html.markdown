---
layout: "venafi"
page_title: "Venafi: venafi_policy"
sidebar_current: "docs-venafi-resource-venafi-policy"
description: |-
  Provides access to read and write certificate policy in Venafi. This can be used to define a new policy.
---

# venafi_policy

Provides access to read and write certificate policy in Venafi. This can be used
to define a new policy (folder in *Trust Protection Platform*; application
and/or issuing template in *Venafi as a Service*).

## Example Usage

```hcl
resource "venafi_policy" "internal_policy" {
    zone = "My Business App\\Enterprise Trusted Certs"
    policy_specification = file("/path-to/internal-policy.json")
}
```

## Argument Reference

The following arguments are supported:

* `zone` - (Required, string) The *Trust Protection Plaform* policy folder or
  *Venafi as a Service* application and issuing template.

* `policy_specification` - (Required, string) The JSON-formatted certificate policy
  specification.  Typically read from a file using the `file` function.

## Import

The `venafi_policy` resource supports the Terraform [import](https://www.terraform.io/docs/cli/import/index.html)
method.  When used, the `zone` and `policy_specification` resource arguments
are not required since the zone is a required parameter of the import method
and the policy specification is populated from the existing infrastructure.
Policy that is successfully imported is also output to a file named after the
zone that was specified.

```hcl
resource "venafi_policy" "existing_policy" {}
```

```sh
terraform import "venafi_policy.existing_policy" "My Business App\\Enterprise Trusted Certs"
```
