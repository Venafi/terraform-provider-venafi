terraform {
  required_providers {
    venafi = {
      source  = "venafi/venafi"
      version = "~> 0.23"
    }
  }
}

# Configure the Venafi Provider
# For CyberArk Certificate Manager, Self-Hosted (TPP)
provider "venafi" {
  url          = var.tpp_url
  access_token = var.tpp_access_token
  zone         = var.tpp_zone
  trust_bundle = file(var.trust_bundle_path)
}

# For CyberArk Certificate Manager, SaaS (VaaS)
# provider "venafi" {
#   api_key = var.vaas_api_key
#   zone    = var.vaas_zone
# }

# Certificate with user-provided CSR
resource "venafi_certificate" "user_csr_certificate" {
  common_name = var.common_name
  csr_origin  = "file"
  csr_pem     = file(var.csr_pem_path)
}
