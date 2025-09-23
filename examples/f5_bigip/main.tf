terraform {
  required_providers {
    venafi = {
      source = "venafi/venafi"
      version = "~> 0.11.0"
    }
    bigip = {
      source = "f5networks/bigip"
      version = "~> 1.5.0"
    }
  }
  required_version = ">= 0.13"
}

// Uncomment for CyberArk Certificate Manager, SaaS
/*
variable "venafi_api_key" {
  type = string
  sensitive = true
}
*/

// Uncomment for CyberArk Certificate Manager, Self-Hosted
/*
variable "tpp_url" {
    type = string
  }
  
  variable "bundle_path" {
    type = string
  }

  variable "access_token" {
    type = string
  }
*/

variable "venafi_zone" {
  type = string
}

variable "test_site_name" {
  type = string
}

variable "test_site_domain" {
  type = string
}

variable "f5_address" {
  type = string
}

variable "f5_username" {
  type = string
}

variable "f5_password" {
  type = string
  sensitive = true
}

variable "f5_partition" {
  type = string
}

variable "f5_virtual_ip" {
  type = string
}

variable "f5_virtual_port" {
  type = string
}

variable "f5_pool_members" {
  type = list(string)
}
