/*
This is an example Terraform file to show capabilities of the VCert integration.
This file uses a service account access token to authenticate to Palo Alto Networks Next-Gen Trust Security (NGTS).
*/
terraform {
  required_providers {
    venafi = {
      source  = "venafi/venafi"
      version = "~> 0.23.2"
    }
  }
  required_version = ">= 0.15"
}

variable "CLOUD_ZONE" {
  type = string
}

variable "URL" {
  type = string
}

variable "TOKEN_URL" {
  type = string
}

variable "CLIENT_ID" {
  type = string
}

variable "CLIENT_SECRET" {
  type = string
}

variable "TSG_ID" {
  type = string
}

provider "venafi" {
  alias         = "ngts"
  url           = var.URL
  token_url     = var.TOKEN_URL
  zone          = var.CLOUD_ZONE
  client_id     = var.CLIENT_ID
  client_secret = var.CLIENT_SECRET
  tsg_id        = var.TSG_ID
}

resource "venafi_certificate" "dev_certificate" {
  //Name of the used provider
  provider    = venafi.ngts
  common_name = "terraform.venafi.example.com"

  //Key encryption algorithm
  algorithm = "RSA"
  rsa_bits  = "2048"

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
  value     = venafi_certificate.dev_certificate.private_key_pem
}
