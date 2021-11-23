resource "null_resource" "remote-exec-windows" {
  triggers = {
    always_run = timestamp()
    admin_user = var.admin_user
    admin_password = sensitive(var.admin_password)
    host = var.host
    winrm_port = var.winrm_port
    execute_destroy = local.execute_destroy
    winrm_ca_trust_path = var.winrm_ca_trust_path
  }
  depends_on = [
    venafi_certificate.tls_server
  ]

  provisioner "file" {
    connection {
      type     = "winrm"
      user     = var.admin_user
      password = var.admin_password
      host     = var.host
      insecure = false
      use_ntlm = true
      cacert   = var.winrm_ca_trust_path != "" ? file(var.winrm_ca_trust_path) : null
      port     = var.winrm_port
      https    = true
      timeout  = "30s"
    }
    source      = "${local.asset_name}.p12"
    destination = "${local.workPath}\\${local.asset_name}.p12"
  }

  provisioner "file" {
    connection {
      type     = "winrm"
      user     = var.admin_user
      password = var.admin_password
      host     = var.host
      insecure = false
      use_ntlm = true
      cacert   = var.winrm_ca_trust_path != "" ? file(var.winrm_ca_trust_path) : null
      port = var.winrm_port
      https = true
      timeout = "30s"
    }
    source      = local.scriptNameWithExt
    destination = "${local.workPath}\\${local.scriptNameWithExt}"
  }

  provisioner "remote-exec" {
    connection {
      type     = "winrm"
      user     = var.admin_user
      password = var.admin_password
      host     = var.host
      insecure = false
      use_ntlm = true
      cacert   = var.winrm_ca_trust_path != "" ? file(var.winrm_ca_trust_path) : null
      port = var.winrm_port
      https = true
      timeout = "30s"
    }
    inline = [<<-EOT
      powershell -f ${local.execute_plan}
    EOT
    ]
  }

  provisioner "remote-exec" {
    when = destroy
    connection {
      type     = "winrm"
      user     = self.triggers.admin_user
      password = self.triggers.admin_password
      host     = self.triggers.host
      insecure = false
      use_ntlm = true
      cacert   = self.triggers.winrm_ca_trust_path != "" ? file(self.triggers.winrm_ca_trust_path) : null
      port = self.triggers.winrm_port
      https = true
      timeout = "30s"
    }
    inline = [<<-EOT
      powershell -f ${self.triggers.execute_destroy}
      EOT
    ]
  }
}
