---
subcategory: "Policy Management"
layout: "venafi"
page_title: "Venafi: venafi_policy"
description: |-
  Provides access to read and write certificate policy in CyberArk Machine Identity Service. This can be used to define a new policy.
---

# venafi_policy

Provides access to read and write certificate policy in CyberArk Machine Identity Service. This can be used to define a new policy (folder in 
*CyberArk Certificate Manager, Self-Hosted*; application and issuing template in *CyberArk Certificate Manager, SaaS*).

## Example Usage

```hcl
resource "venafi_policy" "internal_policy" {
    zone = "My Business App\\Enterprise Trusted Certs"
    policy_specification = file("/path-to/internal-policy.json")
}
```

## Argument Reference

The following arguments are supported:

* `zone` - (Required, string) The *CyberArk Certificate Manager, Self-Hosted* policy folder or *CyberArk Certificate Manager, SaaS* application and 
issuing template.

* `policy_specification` - (Required, string) The JSON-formatted certificate policy specification as documented 
[here](https://github.com/Venafi/vcert/blob/master/README-POLICY-SPEC.md). Typically read from a file using the `file` 
function.

## Import

The `venafi_policy` resource supports the Terraform [import](https://www.terraform.io/docs/cli/import/index.html) method. 
When used, the `zone` and `policy_specification` resource arguments are not required since the zone is a required 
parameter of the import method and the policy specification is populated from the existing infrastructure. Policy that 
is successfully imported is also output to a file named after the zone that was specified.

```hcl
resource "venafi_policy" "existing_policy" {}
```

```sh
terraform import "venafi_policy.existing_policy" "My Business App\\Enterprise Trusted Certs"
```
