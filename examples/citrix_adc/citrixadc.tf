provider "citrixadc" {
  endpoint = "https://${var.citrix_address}/"
  username = var.citrix_username
  password = var.citrix_password
  insecure_skip_verify = true
}

resource "citrixadc_systemfile" "my_certfile" {
  filename = "${venafi_certificate.tls_server.common_name}.cert"
  filelocation = "/nsconfig/ssl"
  filecontent = venafi_certificate.tls_server.certificate
}

resource "citrixadc_systemfile" "my_keyfile" {
  filename = "${venafi_certificate.tls_server.common_name}.key"
  filelocation = "/nsconfig/ssl"
  filecontent = venafi_certificate.tls_server.private_key_pem
}

resource "citrixadc_systemfile" "my_chainfile" {
  filename = "${var.test_site_name}_chain.cert"
  filelocation = "/nsconfig/ssl"
  filecontent = venafi_certificate.tls_server.chain
}

resource "citrixadc_sslcertkey" "my_chain" {
  certkey = "${var.test_site_name}_ca_chain"
  cert = "${citrixadc_systemfile.my_certfile.filelocation}/${citrixadc_systemfile.my_chainfile.filename}"
  bundle = "NO"
  expirymonitor = "DISABLED"
}

resource "citrixadc_sslcertkey" "my_certkey" {
  certkey = "${var.test_site_name}.${var.test_site_domain}"
  cert = "${citrixadc_systemfile.my_certfile.filelocation}/${citrixadc_systemfile.my_certfile.filename}"
  key = "${citrixadc_systemfile.my_keyfile.filelocation}/${citrixadc_systemfile.my_keyfile.filename}"
  expirymonitor = "DISABLED"
  linkcertkeyname = citrixadc_sslcertkey.my_chain.certkey
}

resource "citrixadc_servicegroup" "my_pool" {
  servicegroupname = "${var.test_site_name}_pool"
  servicetype = "HTTP"
  lbvservers = [citrixadc_lbvserver.my_virtual_server.name]
  servicegroupmembers = var.citrix_service_group_members
}

resource "citrixadc_lbvserver" "my_virtual_server" {
  name = "vs_${var.test_site_name}"
  ipv46 = var.citrix_virtual_ip
  port = var.citrix_virtual_port
  servicetype = "SSL"
  lbmethod = "ROUNDROBIN"
  sslcertkey = citrixadc_sslcertkey.my_certkey.certkey
  ciphersuites = ["DEFAULT"]
}
