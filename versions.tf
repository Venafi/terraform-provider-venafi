terraform {
  required_providers {
    random = {
      source = "hashicorp/random"
    }
    venafi = {
      source = "terraform-providers/venafi"
    }
  }
  required_version = ">= 0.13"
}
