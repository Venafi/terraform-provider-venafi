terraform {
  required_providers {
    venafi = {
      source = "venafi/venafi"
      version = "~> 0.12.0"
    }
  }
  required_version = ">= 0.15"
}

locals {
  asset_name = "${var.test_site_name}.${var.test_site_domain}"
  list_tpp_values = tolist([var.tpp_url, var.bundle_path, var.access_token])
  workPath = "C:\\Windows\\Temp"
  scriptNameWithExt = "plan.ps1"
  initFunction = "init"
  destroyFunction = "destroy"
  executeString = "\"${local.workPath}\\${local.scriptNameWithExt}\" -WORK_PATH \"${local.workPath}\" -WEB_NAME \"${var.website_name}\" -ASSET_NAME \"${local.asset_name}\" -BINDING_PORT \"${var.binding_port}\" -BINDING_IP \"${var.binding_ip}\""
  executeStringInit = "${local.executeString} -EXECUTE \"${local.initFunction}\""
  executeStringDestroy = "${local.executeString} -EXECUTE \"${local.destroyFunction}\""
  noHostHeaderString = local.executeStringInit
  hostHeaderAndSSLoffString = "${local.executeStringInit} -SSL_FLAG 0"
  hostHeaderAndSSLonString = "${local.executeStringInit} -SSL_FLAG 1"
  destroyNoHostHeaderString = local.executeStringDestroy
  destroyHostHeaderAndSSLoffString = "${local.executeStringDestroy} -SSL_FLAG 0"
  destroyHostHeaderAndSSLonString = "${local.executeStringDestroy} -SSL_FLAG 1"
  noHostHeader = "${var.ssl_flag == null ? local.noHostHeaderString: "" }"
  hostHeaderAndSSLoff = "${var.ssl_flag == false ? local.hostHeaderAndSSLoffString: "" }"
  hostHeaderAndSSLon = "${var.ssl_flag == true ? local.hostHeaderAndSSLonString: "" }"
  execute_plan = "${coalesce(local.noHostHeader,local.hostHeaderAndSSLoff, local.hostHeaderAndSSLon)}"
  destroyNoHostHeader = "${var.ssl_flag == null ? local.destroyNoHostHeaderString : "" }"
  destroyHostHeaderAndSSLoff = "${var.ssl_flag == false ? local.destroyHostHeaderAndSSLoffString : "" }"
  destroyHostHeaderAndSSLon = "${var.ssl_flag == true ? local.destroyHostHeaderAndSSLonString: "" }"
  execute_destroy = "${coalesce(local.destroyNoHostHeader, local.destroyHostHeaderAndSSLoff, local.destroyHostHeaderAndSSLon)}"
}

#  --- TPP ---

variable "tpp_url" {
  type = string
  default = ""
}

variable "bundle_path" {
  type = string
  default = ""
}

variable "access_token" {
  type = string
  default = ""
}

# --- Venafi as a Service ---

variable "vaas_api_key" {
  type = string
  sensitive = true
  default = ""
}

# ---- Windows Server ----

variable "admin_user" {
  type = string
}

variable "admin_password" {
  type = string
  sensitive = true
}

variable "host" {
  type = string
}

variable "winrm_port" {
  type = string
}

variable "winrm_ca_trust_path" {
  type = string
  default = ""
}

# ----- IIS ----

variable "binding_ip" {
  type = string
}

variable "binding_port" {
  type = string
}

variable "website_name" {
  type = string
}

variable "ssl_flag" {
  type = bool
  default = null
}

# -----------------------

variable "venafi_zone" {
  type = string
}

variable "test_site_name" {
  type = string
}

variable "test_site_domain" {
  type = string
}

# OUTPUTS

output "my_certificate" {
  value = venafi_certificate.tls_server.certificate
}