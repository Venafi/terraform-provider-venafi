# User-Supplied CSR Example

This example demonstrates how to use the Venafi Terraform provider with a user-provided Certificate Signing Request (CSR).

## Overview

This "Bring Your Own CSR" workflow is particularly useful for:

- **HSM-protected private keys**: When private keys are stored in Hardware Security Modules (HSM) and cannot be exported
- **Externally managed key pairs**: When you need to manage private keys outside of Terraform
- **Compliance requirements**: When organizational policies mandate key generation outside of Terraform
- **Migration scenarios**: When migrating from other certificate management systems with existing key pairs

## Prerequisites

1. A Certificate Signing Request (CSR) in PEM format
2. Access to either:
   - CyberArk Certificate Manager, Self-Hosted (TPP) with appropriate credentials and zone
   - CyberArk Certificate Manager, SaaS (VaaS) with API key and zone

## Generating a CSR (Example)

If you need to generate a CSR for testing, you can use OpenSSL:

```bash
# Generate a private key (keep this secure!)
openssl genrsa -out private-key.pem 2048

# Generate a CSR
openssl req -new -key private-key.pem -out certificate.csr \
  -subj "/C=US/ST=Texas/L=Austin/O=Example Org/OU=Engineering/CN=example.venafi.com"

# Verify the CSR
openssl req -in certificate.csr -noout -text
```

For HSM-based workflows, use your HSM's tools to generate the CSR directly on the hardware.

## Usage

1. Create a `terraform.tfvars` file with your configuration:

```hcl
# For CyberArk Certificate Manager, Self-Hosted (TPP)
tpp_url          = "https://tpp.venafi.example"
tpp_access_token = "your-access-token"
tpp_zone         = "DevOps\\Certificates"
trust_bundle_path = "/path/to/bundle.pem"

# For CyberArk Certificate Manager, SaaS (VaaS)
# vaas_api_key = "your-api-key"
# vaas_zone    = "Default"

# Common variables
common_name   = "example.venafi.com"
csr_pem_path = "./certificate.csr"
```

2. Initialize Terraform:

```bash
terraform init
```

3. Plan the deployment:

```bash
terraform plan
```

4. Apply the configuration:

```bash
terraform apply
```

## Important Notes

- **Private Key Management**: When using `csr_origin = "file"`, the private key is NOT stored in Terraform state. You must manage the private key separately and securely.
- **CSR Input**: The CSR is provided via the `csr_pem` attribute using Terraform's `file()` function to read the CSR file content.
- **Common Name**: The `common_name` variable should match the Common Name (CN) in your CSR.
- **Certificate Chain**: The issued certificate and its chain are stored in the Terraform state and can be accessed via outputs.
- **State Security**: Ensure your Terraform state is properly secured according to HashiCorp best practices.

## Outputs

After successful apply, you can retrieve:

- `certificate_id`: The ID of the issued certificate
- `certificate_pem`: The certificate in PEM format
- `certificate_chain`: The certificate chain in PEM format
- `certificate_dn`: The Distinguished Name of the certificate

Example:

```bash
terraform output certificate_pem > certificate.pem
terraform output certificate_chain > chain.pem
```

## Cleanup

To remove the certificate from Terraform management:

```bash
terraform destroy
```

Note: This will retire the certificate in the Venafi platform (unless `skip_retirement` is set in the provider configuration).
