provider "venafi" {
  api_key = var.venafi_api_key
  zone = var.venafi_zone
}

resource "venafi_certificate" "tls_server" {
  common_name = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}.${var.test_site_domain}"
  san_dns = [
    "${var.test_site_name}.${var.test_site_domain}"
  ]
  algorithm = "RSA"
  rsa_bits = 2048
  expiration_window = 720
}
