terraform {
  required_providers {
    venafi = {
      source  = "venafi/venafi"
      version = "0.10.2"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "3.10"
    }
  }
  required_version = ">= 0.13"
}

// Uncomment for Venafi Cloud
/*
variable "venafi_api_key" {
  type = string
  sensitive = true
}
*/

// Uncomment for TPP

variable "tpp_url" {
    type = string
}
  
variable "bundle_path" {
    type = string
}

variable "access_token" {
    type = string
}

variable "venafi_zone" {
  type = string
}

variable "test_site_name" {
  type = string
}

variable "test_site_domain" {
  type = string
}
