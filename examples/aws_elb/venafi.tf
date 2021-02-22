provider "venafi" {
  url          = var.tpp_url
  trust_bundle = file(var.bundle_path)
  access_token = var.access_token
  zone         = var.venafi_zone
}

resource "venafi_certificate" "webserver" {
  common_name = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}.${var.test_site_domain}"
  algorithm   = "RSA"
  rsa_bits    = 2048
  san_dns = [
    "${var.test_site_name}.${var.test_site_domain}"
  ]
}