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
- Add missing documentation to configure an Venafi Provider for EU.

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
