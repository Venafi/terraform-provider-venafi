## 0.16.1 (Oct 7, 2022)
Added support for nickname attribute to override certificate object name at TPP.
Fixed a bug that would let a not valid certificate key-pair to be stored in terraform state during resource creation

## 0.16.0 (May 16, 2022)
Upgraded plugin to SDKv2

## 0.15.5 (April 14, 2022)

Fixed a bug in backward compatibility with PKCS#1 Keys

## 0.15.4 (April 8, 2022)

Added support for SANs attributes

## 0.15.3 (March 31, 2022)

Fixed a bug in expiration_window behavior

## 0.15.2 (March 21, 2022)

Resolved issue that prevented provider from being published to Terraform Registry

## 0.15.1 (March 18, 2022)

Added support for arm64 processors with Darwin OS.

## 0.15.0 (March 14, 2022)

Added support for Certificate importing.

## 0.14.0 (February 8, 2022)

Added support for CSR service generated and retrieval of SSH configuration from template.

## 0.13.0 (September 10, 2021)

Added venafi_ssh_certificate resource that enables SSH certificate creation with Trust Protection Platform.

## 0.12.0 (June 07, 2021)

Added venafi_policy resource that enables certificate policy management with Trust Protection Platform and Venafi as a Service.

## 0.11.2 (February 24, 2021)

Fixing a bug that broke TPP integrations when the customer's zone is in the "long form" way, that is using the "VED" prefix.

## 0.11.1 (February 18, 2021)

Fixing a bug that broke TPP integrations when the customer's zone is more than 2 levels.

## 0.11.0 (February 12, 2021)

Updated Venafi Cloud integration to use OutagePREDICT instead of DevOpsACCELERATE.

## 0.10.2 (October 22, 2020)

Added support for requesting certificates with specific validity periods.

## 0.10.1 (October 7, 2020)

Added support for setting Custom Fields when enrolling certificates with Trust Protection Platform.

## 0.10.0 (September 16, 2020)

Introduced support for Trust Protection Platform Token Authentication ("hashicorp-terraform-by-venafi" API Application).

Added PKCS#12 output format for certificate/key/chain.

## 0.9.4 (September 2, 2020)

New release with NO CODE CHANGES (only minor doc updates) to verify new Terraform Registry release process.

## 0.9.3 (June 29, 2020)

Enabled Source Application Tagging for Venafi Cloud via new VCert version.

## 0.9.2 (March 13, 2020)

Added Source Application Tagging for Trust Protection Platform.

Update to new vcert version with few bug fixes.

## 0.9.0 (December 18, 2019)

Provider migrated to the Terraform Plugin SDK.

## 0.8.0 (October 08, 2019)

Initial release under "terraform-provider"
