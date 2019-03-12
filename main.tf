/*
This is an example terrafrom file to show capabilities of vcert integration.
*/

/*
Setting the provider variables for authentication. You need to add the TF_VAR_ prefix to variables so they can be seen inside Terraform.
Example:
export TF_VAR_TPPUSER='admin'
export TF_VAR_TPPPASSWORD='secret'
export TF_VAR_CLOUDAPIKEY='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx'
export TF_VAR_TPPURL="https://venafi.example.com:5008/vedsdk"
export TF_VAR_TPPZONE="example\\\\zone"
export TF_VAR_CLOUDZONE="Default"
*/

variable "CLOUDAPIKEY" {}
variable "CLOUDZONE" {}
variable "TPPUSER" {}
variable "TPPPASSWORD" {}
variable "TPPURL" {}
variable "TPPZONE" {}
variable "TRUST_BUNDLE" {}

resource "random_string" "cn" {
  length = 5
  special = false
  upper = false
  number = false
}

/*
Here we are configuring thre providers using provider aliases.

Dev provider configuration (alias = "dev") for testing, it don't need any external sources configured.
*/
provider "venafi" {
  alias = "dev"
  dev_mode = true
}

/*
Cloud profivder configuration (alias = "cloud")
Here we are getting credentials from variables TF_VAR_CLOUDAPIKEY and TF_VAR_CLOUDZONE
*/
provider "venafi" {
  alias = "cloud"
  api_key = "${var.CLOUDAPIKEY}"
  zone = "${var.CLOUDZONE}"
}

/*
Platfrom provider configuration (alias = "tpp")
Here we are getting credentials from variables TF_VAR_TPPUSER, TF_VAR_TPPPASSWORD, TF_VAR_TPPURL and TF_VAR_TPPZONE
*/
provider "venafi" {
  alias = "tpp"
  url = "${var.TPPURL}"
  tpp_username = "${var.TPPUSER}"
  tpp_password = "${var.TPPPASSWORD}"
  zone = "${var.TPPZONE}"
  trust_bundle = "${file(var.TRUST_BUNDLE)}"
}

//Certificate resource definition
resource "venafi_certificate" "dev_certificate" {
  //Name of the used provider
  provider = "venafi.dev"
  common_name = "dev-${random_string.cn.result}.venafi.example.com"
  //Key encription algotrythm
  algorithm = "RSA"
  //DNS aliases
  san_dns = [
    "dev-web01-${random_string.cn.result}.example.com",
    "dev-web02-${random_string.cn.result}.example.com"
  ]
  //IP aliases
  san_ip = [
    "10.1.1.1",
    "192.168.0.1"
  ]
  //Email aliases
  san_email = [
    "dev@venafi.com",
    "dev2@venafi.com"
  ]
  //private key password
  key_password = "xxxxx"
}

//outpu certificate
output "cert_certificate_dev" {
  value = "${venafi_certificate.dev_certificate.certificate}"
}

//output certificate chain
output "cert_chain_dev" {
  value = "${venafi_certificate.dev_certificate.chain}"
}

//output private key
output "cert_private_key_dev" {
  value = "${venafi_certificate.dev_certificate.private_key_pem}"
}

resource "venafi_certificate" "dev_certificate_ecdsa" {
  provider = "venafi.dev"
  common_name = "dev-${random_string.cn.result}.venafi.example.com"
  algorithm = "ECDSA"
  san_dns = [
    "dev-web01-${random_string.cn.result}.example.com",
    "dev-web02-${random_string.cn.result}.example.com"
  ]
  san_ip = [
    "10.1.1.1",
    "192.168.0.1"
  ]
  san_email = [
    "dev@venafi.com",
    "dev2@venafi.com"
  ]
  key_password = "xxxxx"
}

output "cert_certificate_dev_ecdsa" {
  value = "${venafi_certificate.dev_certificate_ecdsa.certificate}"
}

output "cert_chain_dev_ecdsa" {
  value = "${venafi_certificate.dev_certificate_ecdsa.chain}"
}

output "cert_private_key_dev_ecdsa" {
  value = "${venafi_certificate.dev_certificate_ecdsa.private_key_pem}"
}

resource "venafi_certificate" "cloud_certificate" {
  provider = "venafi.cloud"
  common_name = "cloud-${random_string.cn.result}.venafi.example.com"
}

output "cert_certificate_cloud" {
  value = "${venafi_certificate.cloud_certificate.certificate}"
}

output "cert_chain_cloud" {
  value = "${venafi_certificate.cloud_certificate.chain}"
}

output "cert_private_key_cloud" {
  value = "${venafi_certificate.cloud_certificate.private_key_pem}"
}

resource "venafi_certificate" "tpp_certificate" {
  provider = "venafi.tpp"
  common_name = "tpp-${random_string.cn.result}.venafi.example.com"
  algorithm = "RSA"
  rsa_bits = "2048"
  san_dns = [
    "tpp-${random_string.cn.result}-web01.example.com",
    "tpp-${random_string.cn.result}-web02.example.com"
  ]
  san_ip = [
    "10.1.1.1",
    "192.168.0.1"
  ]
  san_email = [
    "tpp@venafi.com",
    "tpp2@venafi.com"
  ]
  key_password = "xxxxx"
}

output "cert_certificate_tpp" {
  value = "${venafi_certificate.tpp_certificate.certificate}"
}

output "cert_chain_tpp" {
  value = "${venafi_certificate.tpp_certificate.chain}"
}

output "cert_private_key_tpp" {
  value = "${venafi_certificate.tpp_certificate.private_key_pem}"
}
