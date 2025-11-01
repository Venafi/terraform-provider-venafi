/*
This is an example Terraform file to show capabilities of the VCert integration.
*/


variable "CLOUD_APIKEY" {
  default = ""
}

variable "CLOUD_ZONE" {
  default = ""
}

variable "CLOUD_ZONE_VC_43631" {
  default = ""
}

variable "CLOUD_URL" {
  default = ""
}

variable "TPP_USER" {
  default = ""
}

variable "TPP_PASSWORD" {
  default = ""
}

variable "TPP_URL" {
  default = ""
}

variable "TPP_ZONE" {
  default = ""
}

variable "TRUST_BUNDLE" {
  default = ""
}

variable "TPP_ACCESS_TOKEN" {
  default = ""
}

resource "random_string" "cn" {
  length  = 5
  special = false
  upper   = false
  number  = false
}

/*
Here we are configuring the providers using provider aliases.
Dev provider configuration (alias = "dev") for testing; it doesn't need any external sources configured.
*/
provider "venafi" {
  alias    = "dev"
  dev_mode = true
}

/*
CyberArk Certificate Manager, SaaS provider configuration (alias = "vaas")
Here we are getting credentials from variables TF_VAR_CLOUDAPIKEY and TF_VAR_CLOUDZONE
*/
provider "venafi" {
  alias   = "vaas"
  api_key = var.CLOUD_APIKEY
  zone    = var.CLOUD_ZONE
  url     = var.CLOUD_URL
}

/*
Platform provider configuration (alias = "tpp")
*/
provider "venafi" {
  alias        = "tpp"
  url          = var.TPP_URL
  tpp_username = var.TPP_USER
  tpp_password = var.TPP_PASSWORD
  zone         = var.TPP_ZONE
  trust_bundle = file(var.TRUST_BUNDLE)
}

/*
Platform provider configuration with Token (alias = "tpp_token")
*/
provider "venafi" {
  alias        = "tpp_token"
  url          = var.TPP_URL
  access_token = var.TPP_ACCESS_TOKEN
  zone         = var.TPP_ZONE
  trust_bundle = file(var.TRUST_BUNDLE)
}

//Certificate resource definition
resource "venafi_certificate" "dev_certificate" {
  //Name of the used provider
  provider    = venafi.dev
  common_name = "dev-${random_string.cn.result}.venafi.example.com"

  //Key encryption algorithm
  algorithm = "RSA"

  //DNS aliases
  san_dns = [
    "dev-web01-${random_string.cn.result}.example.com",
    "dev-web02-${random_string.cn.result}.example.com",
  ]

  //IP aliases
  san_ip = [
    "10.1.1.1",
    "192.168.0.1",
  ]

  //Email aliases
  san_email = [
    "dev@venafi.com",
    "dev2@venafi.com",
  ]

  //private key password
  key_password = "xxxxx"
}

//output certificate
output "cert_certificate_dev" {
  value = venafi_certificate.dev_certificate.certificate
}

//output certificate chain
output "cert_chain_dev" {
  value = venafi_certificate.dev_certificate.chain
}

//output private key
output "cert_private_key_dev" {
  sensitive = true
  value = venafi_certificate.dev_certificate.private_key_pem
}

resource "venafi_certificate" "dev_certificate_ecdsa" {
  provider    = venafi.dev
  common_name = "dev-${random_string.cn.result}.venafi.example.com"
  algorithm   = "ECDSA"
  san_dns = [
    "dev-web01-${random_string.cn.result}.example.com",
    "dev-web02-${random_string.cn.result}.example.com",
  ]
  san_ip = [
    "10.1.1.1",
    "192.168.0.1",
  ]
  san_email = [
    "dev@venafi.com",
    "dev2@venafi.com",
  ]
  key_password = "xxxxx"
}

output "cert_certificate_dev_ecdsa" {
  value = venafi_certificate.dev_certificate_ecdsa.certificate
}

output "cert_chain_dev_ecdsa" {
  value = venafi_certificate.dev_certificate_ecdsa.chain
}

output "cert_private_key_dev_ecdsa" {
  sensitive = true
  value = venafi_certificate.dev_certificate_ecdsa.private_key_pem
}

resource "venafi_certificate" "vaas_certificate" {
  provider    = venafi.vaas
  common_name = "vaas-${random_string.cn.result}.venafi.example.com"
}

output "cert_certificate_vaas" {
  value = venafi_certificate.vaas_certificate.certificate
}

output "cert_chain_vaas" {
  value = venafi_certificate.vaas_certificate.chain
}

output "cert_private_key_vaas" {
  sensitive = true
  value = venafi_certificate.vaas_certificate.private_key_pem
}

resource "venafi_certificate" "tpp_certificate" {
  provider    = venafi.tpp
  common_name = "tpp-${random_string.cn.result}.venafi.example.com"
  algorithm   = "RSA"
  rsa_bits    = "2048"
  san_dns = [
    "tpp-${random_string.cn.result}-web01.example.com",
    "tpp-${random_string.cn.result}-web02.example.com",
  ]
  san_ip = [
    "10.1.1.1",
    "192.168.0.1",
  ]
  san_email = [
    "tpp@venafi.com",
    "tpp2@venafi.com",
  ]
  key_password = "xxxxx"
}

output "cert_certificate_tpp" {
  value = venafi_certificate.tpp_certificate.certificate
}

output "cert_chain_tpp" {
  value = venafi_certificate.tpp_certificate.chain
}

output "cert_private_key_tpp" {
  sensitive = true
  value = venafi_certificate.tpp_certificate.private_key_pem
}

resource "venafi_certificate" "token_certificate" {
  provider    = venafi.tpp_token
  common_name = "tpp-${random_string.cn.result}.venafi.example.com"
  algorithm   = "RSA"
  rsa_bits    = "2048"
  san_dns = [
    "tpp-${random_string.cn.result}-web01.example.com",
    "tpp-${random_string.cn.result}-web02.example.com",
  ]
  san_ip = [
    "10.1.1.1",
    "192.168.0.1",
  ]
  san_email = [
    "tpp@venafi.com",
    "tpp2@venafi.com",
  ]
  key_password = "xxxxx"
}

output "cert_certificate_token" {
  value = venafi_certificate.token_certificate.certificate
}

output "cert_chain_tpp_token" {
  value = venafi_certificate.token_certificate.chain
}

output "cert_private_key_token" {
  sensitive = true
  value = venafi_certificate.token_certificate.private_key_pem
}

provider venafi {
  alias = "vc-43631"
  api_key = var.CLOUD_APIKEY
  zone    = var.CLOUD_ZONE_VC_43631
  url     = var.CLOUD_URL
}

resource "venafi_certificate" "VC-43631" {
  provider = venafi.vc-43631
  csr_origin = "service"
  common_name = "VC-43631-${random_string.cn.result}.example.com"
  san_dns = ["VC-43631-${random_string.cn.result}.example.com"]
}

output "cert_certificate_VC-43631" {
  value = venafi_certificate.VC-43631.certificate
}

output "cert_chain_VC-43631" {
  value = venafi_certificate.VC-43631.chain
}

output "cert_private_key_VC-43631" {
  sensitive = true
  value = venafi_certificate.VC-43631.private_key_pem
}