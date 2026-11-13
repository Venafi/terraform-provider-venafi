## 0.24.2 (November 10th, 2026)
- Builds with Go 1.27.3. Earlier Go versions accept certificate chains from the compromised eMudhra intermediate CAs; Go 1.27.3 rejects them, so the provider no longer trusts TLS servers presenting those chains.
- Updates the VCert SDK to v5.14.0.
- Note: CyberArk Certificate Manager, Self-Hosted 26.1 no longer supports the deprecated username/password authentication (`tpp_username`/`tpp_password`); use `access_token` instead.

## 0.24.1 (July 10th, 2026)
- Updates the VCert SDK to v5.13.8, which fixes how certificate validity is handled for ZTPKI ([#218](https://github.com/Venafi/terraform-provider-venafi/pull/218)).

## 0.24.0 (June 22nd, 2026)
- Adds support for Palo Alto Networks Next-Gen Trust Security (NGTS), authenticating with a service account (`client_id`, `client_secret`, `token_url` and `tsg_id`) ([#211](https://github.com/Venafi/terraform-provider-venafi/pull/211)).
- Replaces unmaintained dependencies and updates dependency libraries ([#210](https://github.com/Venafi/terraform-provider-venafi/pull/210), [#213](https://github.com/Venafi/terraform-provider-venafi/pull/213), [#214](https://github.com/Venafi/terraform-provider-venafi/pull/214)).
- Moves linting to golangci-lint v2 ([#216](https://github.com/Venafi/terraform-provider-venafi/pull/216), [#217](https://github.com/Venafi/terraform-provider-venafi/pull/217)).

## 0.23.2 (June 11th, 2026)
- Security: the key password is no longer written to logs when importing a certificate ([#205](https://github.com/Venafi/terraform-provider-venafi/pull/205)).
- Security: the `pkcs12` attribute of `venafi_certificate` and the `private_key` attribute of `venafi_ssh_certificate` are now marked as sensitive ([#206](https://github.com/Venafi/terraform-provider-venafi/pull/206), [#207](https://github.com/Venafi/terraform-provider-venafi/pull/207)).
- Fixes the Terraform state when a cloud keystore installation is deleted outside Terraform in CyberArk Certificate Manager, SaaS ([#208](https://github.com/Venafi/terraform-provider-venafi/pull/208)).
- Updates product names in the documentation, examples, log messages and errors to CyberArk Certificate Manager ([#193](https://github.com/Venafi/terraform-provider-venafi/pull/193), [#194](https://github.com/Venafi/terraform-provider-venafi/pull/194), [#199](https://github.com/Venafi/terraform-provider-venafi/pull/199)).

## 0.23.1 (October 6th, 2025)
- Fixes a crash caused by certain SAN URI regular expressions in a CyberArk Certificate Manager, SaaS zone.

## 0.23.0 (September 5th, 2025)
- Add support to provide certificate tags for Venafi Control Plane.

## 0.22.4 (August 12th, 2025)
- Add support to provide a client certificate in PKCS#12 Base64 format.
 
## 0.22.3 (June 21st, 2025)
- Previous version required to set the `cloud_certificate_name` argument in order to set the `gcm_cert_scope` in [venafi_cloud_keystore_installation](./website/docs/r/venafi_cloud_keystore_installation.html.markdown) resource. Now this restriction doesn't exist.

## 0.22.2 (June 12th, 2025)
- Add support to set GCM Certificate scope in [venafi_cloud_keystore_installation](./website/docs/r/venafi_cloud_keystore_installation.html.markdown) resource.

## 0.22.1 (June 4th, 2025)
- Fixed nil pointer issue [#171](https://github.com/Venafi/terraform-provider-venafi/issues/171)

## 0.22.0 (April 24th, 2025)
- Support TPP v25.1 and higher
- Upgrades Golang build up to v1.23.
- Solves vulnerabilities issues found 

## 0.21.2 (January 22nd, 2025)
- Bumps dependency libraries

## 0.21.1 (September 12th, 2024)
- Fixed linter errors.
- Add missing documentation to configure a Venafi Provider for EU.

## 0.21.0 (June 11th, 2024)
- Added support for Cloud Provisioning in Venafi Control Plane.

## 0.20.0 (April 10th, 2024)
- Changed attribute name from `idp_jwt` to `external_jwt`

## 0.19.0 (April 8th, 2024)
- Added support for service account authentication for Venafi as a Service. Two new attributes have been added 
to the provider: `token_url` and `idp_jwt`. Check [README.md](https://github.com/Venafi/terraform-provider-venafi/blob/master/README.md) 
for more details.
- Added custom User-Agent to identify API calls made by the provider, in the form: `hashicorp-terraform-by-venafi/x.x.x` 
where x is the provider's version.

## 0.18.0 (February 27th, 2024)
- Added support for certificate retirement for both Venafi platforms: Trust Protection Platform and Venafi as a Service.
This action will be executed by default as part of `terraform destroy`. In order to keep previous behavior 
(certificate not retired on destroy), a new boolean attribute `skip_retirement` was added to the provider.

## 0.17.2 (October 6th, 2023)
- Rolls back the error removal from version v0.17.1

## 0.17.1 (October 2nd, 2023)
- Removes an error thrown during provider configuration. Instead, the error is thrown at resource creation.
This change is necessary to allow the venafi-token provider to successfully manage the tokens of this provider.

## 0.17.0 (September 25, 2023)
- Added support for client certificate as authentication method. Two attributes were added for this purpose: 
`p12_cert_filename` (filename of the pkcs12 bundle) and `p12_cert_password` (password of the pkcs12 bundle).
- Added support for `client_id` attribute to allow users to customize which application is requesting tokens. 

## 0.16.1 (October 7, 2022)
- Added support for nickname attribute to override certificate object name at Trust Protection Platform.
- Fixed a bug that would let an invalid certificate key-pair to be stored in terraform state during resource creation.

## 0.16.0 (May 16, 2022)
- Upgraded plugin to SDKv2.

## 0.15.5 (April 14, 2022)
- Fixed a bug in backward compatibility with PKCS#1 Keys.

## 0.15.4 (April 8, 2022)
- Added support for SANs attributes.

## 0.15.3 (March 31, 2022)
- Fixed a bug in `expiration_window` behavior.

## 0.15.2 (March 21, 2022)
- Resolved issue that prevented provider from being published to Terraform Registry.

## 0.15.1 (March 18, 2022)
- Added support for arm64 processors with Darwin OS.

## 0.15.0 (March 14, 2022)
- Added support for certificate importing.

## 0.14.0 (February 8, 2022)
- Added support for service-generated certificate signing requests (CSR) and retrieval of SSH configuration from template.

## 0.13.0 (September 10, 2021)
- Added venafi_ssh_certificate resource that enables SSH certificate creation with Trust Protection Platform.

## 0.12.0 (June 07, 2021)
- Added venafi_policy resource that enables certificate policy management with Trust Protection Platform 
and Venafi as a Service.

## 0.11.2 (February 24, 2021)
- Fixing a bug that broke Trust Protection Platform integration when the customer's zone uses the "VED" prefix, a.k.a. the "long" format.

## 0.11.1 (February 18, 2021)
- Fixing a bug that broke Trust Protection Platform integration when the customer's zone is more than 2 levels.

## 0.11.0 (February 12, 2021)
- Updated Venafi Cloud integration to use OutagePREDICT instead of DevOpsACCELERATE.

## 0.10.2 (October 22, 2020)
- Added support for requesting certificates with specific validity periods.

## 0.10.1 (October 7, 2020)
- Added support for setting Custom Fields when enrolling certificates with Trust Protection Platform.

## 0.10.0 (September 16, 2020)
- Introduced support for Trust Protection Platform Token Authentication ("hashicorp-terraform-by-venafi" API Application). 
- Added PKCS#12 output format for certificate/key/chain.

## 0.9.4 (September 2, 2020)
- New release with NO CODE CHANGES (only minor doc updates) to verify new Terraform Registry release process.

## 0.9.3 (June 29, 2020)
- Enabled Source Application Tagging for Venafi Cloud via new VCert version.

## 0.9.2 (March 13, 2020)
- Added Source Application Tagging for Trust Protection Platform.
- Updated to new vcert version with few bug fixes.

## 0.9.0 (December 18, 2019)
- Provider migrated to the Terraform Plugin SDK.

## 0.8.0 (October 08, 2019)
- Initial release under "terraform-provider".
