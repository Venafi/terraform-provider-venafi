---
subcategory: "Cloud Provisioning"
layout: "venafi"
page_title: "Venafi: venafi_cloud_provider_validation"
description: |-
  Validates a Cloud Provider in CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)
---

# Resource: venafi_cloud_provider_validation

Validates a [venafi_cloud_provider](./venafi_cloud_provider.html.markdown): checks that the platform can reach the
cloud account with the configured credentials. A Cloud Provider must be validated before
[venafi_cloud_keystore](./venafi_cloud_keystore.html.markdown) resources can use it.

Validation usually depends on resources outside the platform, such as an AWS IAM role that trusts the platform or a
GCP service account key, and cloud IAM changes take time to propagate. Creating this resource therefore retries the
validation until it succeeds or the create timeout expires. If it still fails, the error contains the reason the
platform reported, nothing is stored in the state, and the next apply validates again.

## Example Usage

```hcl
resource "venafi_cloud_provider" "aws" {
  name = "Production AWS"
  type = "AWS"
  team = "Cloud Admins"

  aws {
    account_id = "123456789012"
    role       = aws_iam_role.venafi.name
  }
}

# The IAM role trusts the platform using the external ID it generated
resource "aws_iam_role" "venafi" {
  name = "venafi-cloud-provider"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::<platform account>:root" }
      Condition = { StringEquals = { "sts:ExternalId" = venafi_cloud_provider.aws.aws[0].external_id } }
    }]
  })
}

resource "venafi_cloud_provider_validation" "aws" {
  cloud_provider_id = venafi_cloud_provider.aws.id

  # wait for the permissions the platform needs (policy not shown)
  depends_on = [aws_iam_role_policy.venafi]

  # validate again whenever the cloud provider changes
  lifecycle {
    replace_triggered_by = [venafi_cloud_provider.aws]
  }

  timeouts {
    create = "10m"
  }
}

# Referencing the validation, rather than the provider, creates keystores only once the provider is validated
resource "venafi_cloud_keystore" "us_east_1" {
  name              = "us-east-1"
  type              = "ACM"
  cloud_provider_id = venafi_cloud_provider_validation.aws.cloud_provider_id
  team              = "Cloud Admins"

  acm {
    region = "us-east-1"
  }
}
```

## Argument Reference

* `cloud_provider_id` - (Required, string) ID of the Cloud Provider to validate. Changing it validates the new Cloud Provider.
* `triggers` - (Optional, map of strings) Arbitrary values that cause the Cloud Provider to be validated again when they change, for example the version of a rotated secret.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - The ID of the validated Cloud Provider.
* `status` - Validation status of the Cloud Provider: `VALIDATED`.

## Timeouts

* `create` - (Default `5m`) How long to keep retrying the validation.

## Drift

The platform sets a Cloud Provider back to `NOT_VALIDATED` when its configuration changes, for example a new AWS role,
or when a later validation fails. When that happens, this resource is removed from the state on the next refresh, and
the plan shows it being created again, which validates the Cloud Provider again.

The platform does not re-validate Cloud Providers on its own, so a credential that stops working outside of Terraform,
such as a deleted IAM role, is only noticed when the Cloud Provider is next validated or used. Use `triggers` or
`replace_triggered_by` to validate again when the resources it depends on change.

## Import

Using `terraform import`, import the validation of a Cloud Provider using the Cloud Provider ID. For example:

```console
terraform import venafi_cloud_provider_validation.example 2155bd32-2234-22ac-7cfd-ff1198845aa2
```
