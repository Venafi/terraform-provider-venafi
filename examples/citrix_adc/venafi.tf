# --- Venafi Cloud ---
# Uncomment for Venafi Cloud

# provider "venafi" {
#   api_key = var.venafi_api_key
#   zone    = var.venafi_zone
# }

#  --- TPP ---
# Uncomment for Venafi Trust Protection Platform

# provider "venafi" {
#   url          = var.tpp_url
#   trust_bundle = file(var.bundle_path)
#   access_token = var.access_token
#   zone         = var.venafi_zone
# }

# ----

resource "venafi_certificate" "tls_server" {
  common_name = "${var.test_site_name}.${var.test_site_domain}"
  san_dns = [
    "${var.test_site_name}.${var.test_site_domain}"
  ]
  algorithm = "RSA"
  rsa_bits = "2048"
  expiration_window = 168
}

# OUTPUTS

output "my_private_key" {
  value = venafi_certificate.tls_server.private_key_pem
  sensitive = true
}

output "my_certificate" {
  value = venafi_certificate.tls_server.certificate
}

output "my_trust_chain" {
  value = venafi_certificate.tls_server.chain
}

output "my_p12_keystore" {
  value = venafi_certificate.tls_server.pkcs12
}
