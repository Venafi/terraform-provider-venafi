provider "bigip" {
  address  = var.f5_address
  username = var.f5_username
  password = var.f5_password
}

locals {
  asset_name = "${var.test_site_name}.${var.test_site_domain}"
}

resource "bigip_ssl_key" "my_key" {
  name      = "${local.asset_name}.key"
  content   = venafi_certificate.tls_server.private_key_pem
  partition = var.f5_partition
}

resource "bigip_ssl_certificate" "my_cert" {
  name      = "${local.asset_name}.crt"
  content   = venafi_certificate.tls_server.certificate
  partition = var.f5_partition
}

resource "bigip_ssl_certificate" "my_chain" {
  name      = "${local.asset_name}-ca-bundle.crt"
  content   = venafi_certificate.tls_server.chain
  partition = var.f5_partition
}

resource "bigip_ltm_profile_client_ssl" "my_profile" {
  name           = "/${var.f5_partition}/clientssl_${var.test_site_name}"
  defaults_from  = "/Common/clientssl"
  cert_key_chain {
    name  = bigip_ssl_certificate.my_cert.name
    cert  = "/${var.f5_partition}/${bigip_ssl_certificate.my_cert.name}"
    key   = "/${var.f5_partition}/${bigip_ssl_key.my_key.name}"
    chain = "/${var.f5_partition}/${bigip_ssl_certificate.my_chain.name}"
  }
}

resource "bigip_ltm_pool" "my_pool" {
  name                   = "/${var.f5_partition}/pool_${var.test_site_name}"
  load_balancing_mode    = "round-robin"
  minimum_active_members = 1
  monitors               = ["/Common/http"]
}

resource "bigip_ltm_pool_attachment" "my_pool_node" {
  pool     = bigip_ltm_pool.my_pool.name
  for_each = toset(var.f5_pool_members)
  node     = each.key
}

resource "bigip_ltm_virtual_server" "my_virtual_server" {
  name                       = "/${var.f5_partition}/vs_${var.test_site_name}"
  description                = "Provisioned by Terraform"
  destination                = var.f5_virtual_ip
  port                       = var.f5_virtual_port
  client_profiles            = [bigip_ltm_profile_client_ssl.my_profile.name]
  source_address_translation = "automap"
  pool                       = bigip_ltm_pool.my_pool.name
}
