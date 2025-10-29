---
subcategory: "Certificate Issuance"
layout: "venafi"
page_title: "CyberArk: venafi_ssh_config"
description: |-
  Provides access to retrieve configuration from SSH certificate issuance template from CyberArk Certificate Manager, Self-Hosted.
---

# venafi_ssh_certificate

Provides access to retrieve configuration from SSH certificate issuance template from *CyberArk Certificate Manager, Self-Hosted*.

## Example Usage

```hcl
resource "venafi_ssh_config" "cit" {
    template = "devops-terraform-cit"
}
```

## Argument Reference

The following argument is supported:

* `template` - (Required, string) The SSH certificate issuing template.


## Attributes Reference

The following attributes are exported:

* `principals` - (Optional, set of strings) A list of user names exported from the template.

* `ca_public_key` - (Optional, string) The template's CA public key.
