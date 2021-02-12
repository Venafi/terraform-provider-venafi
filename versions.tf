terraform {
  required_providers {
    random = {
      source = "hashicorp/random"
    }
    venafi = {
      source = "Venafi/venafi"
    }
  }
  required_version = ">= 0.13"
}
