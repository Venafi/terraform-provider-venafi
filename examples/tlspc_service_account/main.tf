/*
This is an example Terraform file to show capabilities of the VCert integration.
This file uses a service account access token to authenticate to CyberArk Certificate Manager, SaaS.
*/
variable "CLOUD_ZONE" {
  type = string
}

variable "TOKEN_URL" {
  type = string
}

variable "EXTERNAL_JWT" {
  type = string
}

provider "venafi" {
  alias = "dev"
  token_url = var.TOKEN_URL
  external_jwt = var.EXTERNAL_JWT
  zone = var.CLOUD_ZONE
}

resource "venafi_certificate" "dev_certificate" {
  //Name of the used provider
  provider    = venafi.dev
  common_name = "terraform.venafi.example.com"

  //Key encryption algorithm
  algorithm = "RSA"
  rsa_bits    = "2048"

  csr_origin = "local"
}

output "cert_certificate" {
  value = venafi_certificate.dev_certificate.certificate
}

output "cert_chain" {
  value = venafi_certificate.dev_certificate.chain
}

output "cert_private_key" {
  sensitive = true
  value = venafi_certificate.dev_certificate.private_key_pem
}