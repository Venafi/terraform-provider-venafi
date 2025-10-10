terraform {
  required_providers {
    venafi = {
      source = "venafi/venafi"
      version = "~> 0.11.2"
    }
    citrixadc = {
      source = "citrix/citrixadc"
      version = "~> 1.0.0"
    }
  }
  required_version = ">= 0.13"
}

#  --- CyberArk Certificate Manager, Self-Hosted ---
# Uncomment for CyberArk Certificate Manager, Self-Hosted

# variable "tpp_url" {
#   type = string
# }

# variable "bundle_path" {
#   type = string
# }

# variable "access_token" {
#   type = string
# }

# --- CyberArk Certificate Manager, SaaS ---
# Uncomment for CyberArk Certificate Manager, SaaS

# variable "venafi_api_key" {
#   type = string
#   sensitive = true
# }

# ---------

variable "venafi_zone" {
  type = string
}

variable "test_site_name" {
  type = string
}

variable "test_site_domain" {
  type = string
}

variable "citrix_address" {
  type = string
}

variable "citrix_username" {
  type = string
}

variable "citrix_password" {
  type = string
  sensitive = true
}

variable "citrix_virtual_ip"{
  type = string
}

variable "citrix_virtual_port"{
  type = string
}

variable "citrix_service_group_members"{
  type = list(string)
}
