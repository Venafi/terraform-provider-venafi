# Common variables
variable "common_name" {
  description = "The common name for the certificate (must match the CN in the CSR)"
  type        = string
  default     = "example.venafi.com"
}

variable "csr_pem_path" {
  description = "Path to the Certificate Signing Request (CSR) file in PEM format (will be read using file() function)"
  type        = string
  default     = "./certificate.csr"
}

# CyberArk Certificate Manager, Self-Hosted (TPP) variables
variable "tpp_url" {
  description = "The URL of the CyberArk Certificate Manager, Self-Hosted server"
  type        = string
  default     = "https://tpp.venafi.example"
}

variable "tpp_access_token" {
  description = "Access token for CyberArk Certificate Manager, Self-Hosted authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "tpp_zone" {
  description = "Policy folder path for CyberArk Certificate Manager, Self-Hosted"
  type        = string
  default     = "DevOps\\Certificates"
}

variable "trust_bundle_path" {
  description = "Path to the trust bundle file for CyberArk Certificate Manager, Self-Hosted TLS verification"
  type        = string
  default     = "/opt/venafi/bundle.pem"
}

# CyberArk Certificate Manager, SaaS (VaaS) variables
variable "vaas_api_key" {
  description = "API key for CyberArk Certificate Manager, SaaS authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "vaas_zone" {
  description = "Zone name for CyberArk Certificate Manager, SaaS"
  type        = string
  default     = "Default"
}
