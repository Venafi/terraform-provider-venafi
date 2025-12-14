output "certificate_id" {
  description = "The ID of the issued certificate"
  value       = venafi_certificate.user_csr_certificate.id
}

output "certificate_pem" {
  description = "The certificate in PEM format"
  value       = venafi_certificate.user_csr_certificate.certificate
}

output "certificate_chain" {
  description = "The certificate chain in PEM format"
  value       = venafi_certificate.user_csr_certificate.chain
}

output "certificate_dn" {
  description = "The Distinguished Name of the certificate"
  value       = venafi_certificate.user_csr_certificate.certificate_dn
}
