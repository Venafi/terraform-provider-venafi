provider "venafi" {
  url          = var.tpp_url != "" && var.vaas_api_key == "" ? var.tpp_url : null
  trust_bundle = var.bundle_path != "" && var.vaas_api_key == "" ? file(var.bundle_path) : null
  access_token = var.access_token != "" && var.vaas_api_key == "" ? var.access_token : null
  api_key = var.vaas_api_key != "" && length(compact((local.list_tpp_values))) == 0 ? var.vaas_api_key : null
  zone         = var.venafi_zone
}

resource "venafi_certificate" "tls_server" {
  common_name = local.asset_name
  san_dns = [
    local.asset_name
  ]
  algorithm = "RSA"
  rsa_bits = "2048"
  expiration_window = 168

  // Adding our p12 certificate our current path to upload later to our desired resource
  provisioner "local-exec" {
    interpreter = ["/bin/bash" ,"-c"]
    command = "echo '${venafi_certificate.tls_server.pkcs12}' > ${local.asset_name}.p12"
  }

  # Using PowerShell
  // Adding our p12 certificate our current path to upload later to our desired resource
  // provisioner "local-exec" {
  //   interpreter = ["PowerShell", "-Command"]
  //   command = "'${venafi_certificate.tls_server.pkcs12}' > ${local.asset_name}.p12"
  // }
}
