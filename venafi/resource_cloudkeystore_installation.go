package venafi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/verror"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/ngts"
)

const (
	cloudKeystoreInstallationID                       = "id"
	cloudKeystoreInstallationKeystoreID               = "cloud_keystore_id"
	cloudKeystoreInstallationCertificateID            = "certificate_id"
	cloudKeystoreInstallationCloudCertificateName     = "cloud_certificate_name"
	cloudKeystoreInstallationARN                      = "arn"
	cloudKeystoreInstallationGCMCertScope             = "gcm_cert_scope"
	cloudKeystoreInstallationCloudCertificateID       = "cloud_certificate_id"
	cloudKeystoreInstallationCloudCertificateMetadata = "cloud_certificate_metadata"
)

func resourceCloudKeystoreInstallation() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCloudKeystoreInstallationCreate,
		ReadContext:   resourceCloudKeystoreInstallationRead,
		UpdateContext: resourceCloudKeystoreInstallationUpdate,
		DeleteContext: resourceCloudKeystoreInstallationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceCloudKeystoreInstallationImport,
		},
		Schema: map[string]*schema.Schema{
			cloudKeystoreInstallationKeystoreID: {
				Type:        schema.TypeString,
				Description: "ID of the cloud keystore where the certificate will be provisioned",
				Required:    true,
				ForceNew:    true,
			},
			cloudKeystoreInstallationCertificateID: {
				Type:        schema.TypeString,
				Description: "ID of the certificate to be provisioned to the cloud keystore",
				Required:    true,
			},
			cloudKeystoreInstallationCloudCertificateName: {
				Type:             schema.TypeString,
				Description:      "Name the certificate will be identified as in the cloud keystore. Only used when provisioning for AKV and GCM keystores",
				Optional:         true,
				ForceNew:         true,
				DiffSuppressFunc: diffSuppressFuncCloudCertificateName,
			},
			cloudKeystoreInstallationARN: {
				Type:        schema.TypeString,
				Description: "ARN of the certificate in AWS. Only used when provisioning for ACM keystore",
				Optional:    true,
				ForceNew:    true,
			},
			cloudKeystoreInstallationGCMCertScope: {
				Type:        schema.TypeString,
				Description: "Certificate scope of the certificate in Google Cloud. Only used when provisioning for GCM keystore",
				Optional:    true,
			},
			cloudKeystoreInstallationCloudCertificateID: {
				Type:        schema.TypeString,
				Description: "ID of the certificate after it has been provisioned to the cloud keystore",
				Computed:    true,
			},
			cloudKeystoreInstallationCloudCertificateMetadata: {
				Type:        schema.TypeMap,
				Description: "Metadata of the certificate after it has been provisioned to the cloud keystore",
				Computed:    true,
				Elem: &schema.Schema{
					Type:     schema.TypeString,
					Computed: true,
				},
			},
		},
	}
}

func resourceCloudKeystoreInstallationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keystoreID := d.Get(cloudKeystoreInstallationKeystoreID).(string)
	certificateID := d.Get(cloudKeystoreInstallationCertificateID).(string)
	provisionOptionsMap := map[string]string{}
	logFieldsMap := map[string]interface{}{
		cloudKeystoreInstallationKeystoreID:    keystoreID,
		cloudKeystoreInstallationCertificateID: certificateID,
	}
	cloudCertificateNameInterface, cerNameOk := d.GetOk(cloudKeystoreInstallationCloudCertificateName)
	cloudCertificateName := ""
	if cerNameOk {
		cloudCertificateName = cloudCertificateNameInterface.(string)
		logFieldsMap[cloudKeystoreInstallationCloudCertificateName] = cloudCertificateName
		provisionOptionsMap[cloudKeystoreInstallationCloudCertificateName] = cloudCertificateName
	}
	certificateARNInterface, arnOk := d.GetOk(cloudKeystoreInstallationARN)
	certificateARN := ""
	if arnOk {
		certificateARN = certificateARNInterface.(string)
		logFieldsMap[cloudKeystoreInstallationARN] = certificateARN
		provisionOptionsMap[cloudKeystoreInstallationARN] = certificateARN
	}
	certificateGCMCertScopeInterface, gcmCertScopeOk := d.GetOk(cloudKeystoreInstallationGCMCertScope)
	certificateGCMCertScope := ""
	if gcmCertScopeOk {
		certificateGCMCertScope = certificateGCMCertScopeInterface.(string)
		logFieldsMap[cloudKeystoreInstallationGCMCertScope] = certificateGCMCertScope
		provisionOptionsMap[cloudKeystoreInstallationGCMCertScope] = certificateGCMCertScope
	}
	tflog.Info(ctx, "creating cloud keystore installation", logFieldsMap)

	connector, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	// Check Connector is CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)
	if !(connector.GetType() == endpoint.ConnectorTypeCloud || connector.GetType() == endpoint.ConnectorTypeNGTS) {
		return buildStandardDiagError(fmt.Sprintf("Platform detected as [%s]. Cloud Keystore Installation resource is only available for %s or %s", connector.GetType(), endpoint.ConnectorTypeCloud, endpoint.ConnectorTypeNGTS))
	}

	// Check certificate is CSR service generated
	isService, err := connector.IsCSRServiceGenerated(&certificate.Request{
		CertID: certificateID,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	if !isService {
		return buildStandardDiagError(fmt.Sprintf("Cloud Keystore Installation resource only supports certificates whose CSR was generated by %s", connector.GetType()))
	}

	// Get parent CloudKeystore
	var cloudKeystore *domain.CloudKeystore
	switch conn := connector.(type) {
	case *cloud.Connector:
		cloudKeystore, err = conn.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudKeystoreID: &keystoreID,
		})
	case *ngts.Connector:
		cloudKeystore, err = conn.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudKeystoreID: &keystoreID,
		})
	default:
		return buildStandardDiagError(fmt.Sprintf("connector type not supported %s", connector.GetType()))
	}
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, fmt.Sprintf("successfully retrieved cloud keystore installation from %s", connector.GetType()), logFieldsMap)

	// Provision certificate to keystore
	options := getProvisioningOptions(ctx, cloudKeystore.Type, provisionOptionsMap)
	request := &domain.ProvisioningRequest{
		CertificateID: &certificateID,
		KeystoreID:    &keystoreID,
	}

	metadata, err := connector.ProvisionCertificate(request, options)
	if err != nil {
		return diag.FromErr(err)
	}
	logFieldsMap[cloudKeystoreInstallationID] = metadata.MachineIdentityID
	tflog.Info(ctx, "successfully provisioned certificate to cloud keystore", logFieldsMap)

	// Get newly created machine identity
	machineIdentity, err := getMachineIdentity(ctx, metadata.MachineIdentityID, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, fmt.Sprintf("successfully retrieved machine identity from %s", connector.GetType()), logFieldsMap)

	// Store machine identity in state
	err = storeMachineIdentityInState(machineIdentity, d)
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "cloud keystore installation stored in state", logFieldsMap)

	tflog.Info(ctx, "cloud keystore installation created", logFieldsMap)
	return diag.Diagnostics{}
}

func resourceCloudKeystoreInstallationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Id()
	logFieldsMap := map[string]interface{}{cloudKeystoreInstallationID: id}
	tflog.Info(ctx, "reading cloud keystore installation", logFieldsMap)

	// Get machine identity
	machineIdentity, err := getMachineIdentity(ctx, id, meta)
	if err != nil {
		if errors.Is(err, verror.CloudMachineIdentityNotFoundError) {
			tflog.Info(ctx, "machine identity not found", logFieldsMap)
			d.SetId("")
		} else {
			return diag.FromErr(err)
		}
	} else {
		tflog.Info(ctx, "successfully retrieved machine identity", logFieldsMap)

		// Store machine identity in state
		err = storeMachineIdentityInState(machineIdentity, d)
		if err != nil {
			return diag.FromErr(err)
		}
		tflog.Info(ctx, "cloud keystore installation stored in state", logFieldsMap)

		tflog.Info(ctx, "cloud keystore installation read", logFieldsMap)
	}

	return diag.Diagnostics{}
}

func resourceCloudKeystoreInstallationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	machineIdentityID := d.Id()
	certificateID := d.Get(cloudKeystoreInstallationCertificateID).(string)
	logFieldsMap := map[string]interface{}{
		cloudKeystoreInstallationID:            machineIdentityID,
		cloudKeystoreInstallationCertificateID: certificateID,
	}
	tflog.Info(ctx, "updating cloud keystore installation", logFieldsMap)

	connector, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	// Check Connector is CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)
	if !(connector.GetType() == endpoint.ConnectorTypeCloud || connector.GetType() == endpoint.ConnectorTypeNGTS) {
		return buildStandardDiagError(fmt.Sprintf("Platform detected as [%s]. Cloud Keystore Installation resource is only available for %s or %s", connector.GetType(), endpoint.ConnectorTypeCloud, endpoint.ConnectorTypeNGTS))
	}

	// Check certificate is CSR service generated
	isService, err := connector.IsCSRServiceGenerated(&certificate.Request{
		CertID: certificateID,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	if !isService {
		return buildStandardDiagError(fmt.Sprintf("Cloud Keystore Installation resource only supports certificates whose CSR was generated by %s", connector.GetType()))
	}

	var metadata *domain.ProvisioningMetadata
	switch conn := connector.(type) {
	case *cloud.Connector:
		metadata, err = conn.ProvisionCertificateToMachineIdentity(domain.ProvisioningRequest{
			MachineIdentityID: &machineIdentityID,
			CertificateID:     &certificateID,
		})
	case *ngts.Connector:
		metadata, err = conn.ProvisionCertificateToMachineIdentity(domain.ProvisioningRequest{
			MachineIdentityID: &machineIdentityID,
			CertificateID:     &certificateID,
		})
	default:
		return buildStandardDiagError(fmt.Sprintf("connector type not supported %s", connector.GetType()))
	}
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, fmt.Sprintf("successfully provisioned certificate to existing machine identity in %s", connector.GetType()), logFieldsMap)

	// Get newly created machine identity
	machineIdentity, err := getMachineIdentity(ctx, metadata.MachineIdentityID, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, fmt.Sprintf("successfully retrieved machine identity from %s", connector.GetType()), logFieldsMap)

	// Store machine identity in state
	err = storeMachineIdentityInState(machineIdentity, d)
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "cloud keystore installation stored in state", logFieldsMap)

	tflog.Info(ctx, "cloud keystore installation updated", logFieldsMap)
	return diag.Diagnostics{}
}

func resourceCloudKeystoreInstallationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	machineIdentityID := d.Id()
	logFieldsMap := map[string]interface{}{
		cloudKeystoreInstallationID: machineIdentityID,
	}
	tflog.Info(ctx, "deleting cloud keystore installation", logFieldsMap)

	// Remove id from state
	tflog.Info(ctx, "Certificate will be retired when destroyed and Machine Identity deletion will be handled by CyberArk Certificate Manager, SaaS. Removing from terraform state only")
	d.SetId("")
	tflog.Info(ctx, "cloud keystore installation deleted", logFieldsMap)
	return diag.Diagnostics{}
}

func resourceCloudKeystoreInstallationImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	logFieldsMap := map[string]interface{}{cloudKeystoreInstallationID: id}
	tflog.Info(ctx, "importing cloud keystore installation", logFieldsMap)

	if id == "" {
		return nil, fmt.Errorf("cloud keystore installation ID is empty")
	}

	// Get machine identity
	machineIdentity, err := getMachineIdentity(ctx, id, meta)
	if err != nil {
		return nil, err
	}
	tflog.Info(ctx, "successfully retrieved machine identity", logFieldsMap)

	// Store machine identity in state
	err = storeMachineIdentityInState(machineIdentity, d)
	if err != nil {
		return nil, err
	}
	tflog.Info(ctx, "cloud keystore installation stored in state", logFieldsMap)

	tflog.Info(ctx, "cloud keystore installation imported", logFieldsMap)
	return []*schema.ResourceData{d}, nil
}

func getProvisioningOptions(ctx context.Context, cloudKeystoreType domain.CloudKeystoreType, provisionOptionsMap map[string]string) *domain.ProvisioningOptions {
	provisioningOptions := &domain.ProvisioningOptions{}
	var optionsProvided bool
	switch cloudKeystoreType {
	case domain.CloudKeystoreTypeACM:
		arn, ok := provisionOptionsMap[cloudKeystoreInstallationARN]
		if ok && arn != "" {
			tflog.Info(ctx, "using provisioning options", map[string]interface{}{
				cloudKeystoreInstallationARN: arn,
			})
			provisioningOptions.ARN = arn
			optionsProvided = true
		}
	case domain.CloudKeystoreTypeAKV:
		certificateName, ok := provisionOptionsMap[cloudKeystoreInstallationCloudCertificateName]
		if ok && certificateName != "" {
			normalizedCertName := normalizeCloudCertificateName(certificateName)
			tflog.Info(ctx, "using provisioning options", map[string]interface{}{
				cloudKeystoreInstallationCloudCertificateName: normalizedCertName,
			})
			provisioningOptions.CloudCertificateName = normalizedCertName
			optionsProvided = true
		}
	case domain.CloudKeystoreTypeGCM:
		certificateName, ok := provisionOptionsMap[cloudKeystoreInstallationCloudCertificateName]
		if ok && certificateName != "" {
			normalizedCertName := normalizeCloudCertificateName(certificateName)
			tflog.Info(ctx, "using provisioning options", map[string]interface{}{
				cloudKeystoreInstallationCloudCertificateName: normalizedCertName,
			})
			provisioningOptions.CloudCertificateName = normalizedCertName
			optionsProvided = true
		}

		gcmCertScope, ok := provisionOptionsMap[cloudKeystoreInstallationGCMCertScope]
		if ok && gcmCertScope != "" {
			tflog.Info(ctx, "using provisioning options", map[string]interface{}{
				cloudKeystoreInstallationGCMCertScope: gcmCertScope,
			})
			provisioningOptions.GCMCertificateScope = domain.GetScopeFromString(gcmCertScope)
			optionsProvided = true
		}
	default:
		optionsProvided = false
	}

	if optionsProvided {
		return provisioningOptions
	}

	return nil
}

func getMachineIdentity(ctx context.Context, machineIdentityID string, meta interface{}) (*domain.CloudMachineIdentity, error) {
	connector, err := getConnection(ctx, meta)
	if err != nil {
		return nil, err
	}

	// Check Connector is CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)
	if !(connector.GetType() == endpoint.ConnectorTypeCloud || connector.GetType() == endpoint.ConnectorTypeNGTS) {
		return nil, fmt.Errorf("Platform detected as [%s]. Cloud Keystore Installation resource is only available for %s or %s", connector.GetType(), endpoint.ConnectorTypeCloud, endpoint.ConnectorTypeNGTS)
	}

	// Get machine identity
	request := domain.GetCloudMachineIdentityRequest{
		MachineIdentityID: &machineIdentityID,
	}
	var machineIdentity *domain.CloudMachineIdentity
	switch conn := connector.(type) {
	case *cloud.Connector:
		machineIdentity, err = conn.GetMachineIdentity(request)
	case *ngts.Connector:
		machineIdentity, err = conn.GetMachineIdentity(request)
	default:
		return nil, fmt.Errorf("connector type not supported %s", connector.GetType())
	}
	if err != nil {
		return nil, err
	}

	return machineIdentity, nil
}

func storeMachineIdentityInState(machineIdentity *domain.CloudMachineIdentity, d *schema.ResourceData) error {
	if machineIdentity == nil {
		return fmt.Errorf("cannot store machine identity. CloudMachineIdenity object is nil")
	}
	if d == nil {
		return fmt.Errorf("cannot store machine identity. ResourceData object is nil")
	}

	// Store values in state
	err := d.Set(cloudKeystoreInstallationKeystoreID, machineIdentity.CloudKeystoreID)
	if err != nil {
		return err
	}
	err = d.Set(cloudKeystoreInstallationCertificateID, machineIdentity.CertificateID)
	if err != nil {
		return err
	}

	if machineIdentity.Metadata != nil {
		cloudID, err := getCloudIDFromMachineIdentity(machineIdentity.Metadata)
		if err != nil {
			return err
		}
		err = d.Set(cloudKeystoreInstallationCloudCertificateID, cloudID)
		if err != nil {
			return err
		}
		metadataMap, err := getMetadataMapFromMachineIdentity(machineIdentity.Metadata)
		if err != nil {
			return err
		}
		err = d.Set(cloudKeystoreInstallationCloudCertificateMetadata, metadataMap)
		if err != nil {
			return err
		}

		if machineIdentity.Metadata.GetKeystoreType() == domain.CloudKeystoreTypeACM {
			arn, err := getCloudIDFromMachineIdentityACM(machineIdentity.Metadata)
			if err != nil {
				return err
			}
			if arn != "" {
				err = d.Set(cloudKeystoreInstallationARN, arn)
				if err != nil {
					return err
				}
			}
		}

		if machineIdentity.Metadata.GetKeystoreType() != domain.CloudKeystoreTypeACM {
			cloudCertificateName, err := getCloudCertNameFromMachineIdentity(machineIdentity.Metadata)
			if err != nil {
				return err
			}
			if cloudCertificateName != "" {
				err = d.Set(cloudKeystoreInstallationCloudCertificateName, cloudCertificateName)
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(machineIdentity.ID)
	return nil
}

func getCloudCertNameFromMachineIdentity(metadata *domain.CertificateCloudMetadata) (string, error) {
	keystoreType := metadata.GetKeystoreType()
	if keystoreType == domain.CloudKeystoreTypeAKV || keystoreType == domain.CloudKeystoreTypeGCM {
		name, err := getAttributeFromMachineIdentity(metadata, "name")
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", nil
}

func getCloudIDFromMachineIdentity(metadata *domain.CertificateCloudMetadata) (string, error) {
	keystoreType := metadata.GetKeystoreType()
	switch keystoreType {
	case domain.CloudKeystoreTypeACM:
		return getCloudIDFromMachineIdentityACM(metadata)
	case domain.CloudKeystoreTypeAKV:
		return getCloudIDFromMachineIdentityAKV(metadata)
	case domain.CloudKeystoreTypeGCM:
		return getCloudIDFromMachineIdentityGCM(metadata)
	default:
		return "", fmt.Errorf("unexpected cloud metadata type: %s", keystoreType)
	}
}

func getMetadataMapFromMachineIdentity(metadata *domain.CertificateCloudMetadata) (map[string]string, error) {
	metadataMap := make(map[string]string)
	if metadata == nil {
		return nil, fmt.Errorf("cloud metadata is nil")
	}
	if metadata.GetKeystoreType() == domain.CloudKeystoreTypeACM {
		return getMetadataMapFromMachineIdentityACM(metadata)
	}
	if metadata.GetKeystoreType() == domain.CloudKeystoreTypeAKV {
		return getMetadataMapFromMachineIdentityAKV(metadata)
	}
	if metadata.GetKeystoreType() == domain.CloudKeystoreTypeGCM {
		return getMetadataMapFromMachineIdentityGCM(metadata)
	}

	return metadataMap, nil
}

func getCloudIDFromMachineIdentityACM(metadata *domain.CertificateCloudMetadata) (string, error) {
	return getAttributeFromMachineIdentity(metadata, "arn")
}

func getCloudIDFromMachineIdentityAKV(metadata *domain.CertificateCloudMetadata) (string, error) {
	return getAttributeFromMachineIdentity(metadata, "azureId")
}

func getCloudIDFromMachineIdentityGCM(metadata *domain.CertificateCloudMetadata) (string, error) {
	return getAttributeFromMachineIdentity(metadata, "gcpId")
}

func getAttributeFromMachineIdentity(metadata *domain.CertificateCloudMetadata, attribute string) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("cloud metadata is nil")
	}
	val := metadata.GetValue(attribute)
	if val == nil {
		return "", fmt.Errorf("%s not found in metadata", attribute)
	}
	if _, ok := val.(string); !ok {
		return "", fmt.Errorf("unexpected type for %s. Expected string, got %T", attribute, val)
	}

	return val.(string), nil
}

func getMetadataMapFromMachineIdentityACM(metadata *domain.CertificateCloudMetadata) (map[string]string, error) {
	metadataMap := make(map[string]string)

	arn, err := getCloudIDFromMachineIdentityACM(metadata)
	if err != nil {
		return nil, err
	}

	metadataMap["type"] = domain.CloudKeystoreTypeACM.String()
	metadataMap["arn"] = arn

	return metadataMap, nil
}

func getMetadataMapFromMachineIdentityAKV(metadata *domain.CertificateCloudMetadata) (map[string]string, error) {
	metadataMap := make(map[string]string)

	id, err := getCloudIDFromMachineIdentityAKV(metadata)
	if err != nil {
		return nil, err
	}
	name, err := getAttributeFromMachineIdentity(metadata, "name")
	if err != nil {
		return nil, err
	}
	version, err := getAttributeFromMachineIdentity(metadata, "version")
	if err != nil {
		return nil, err
	}

	metadataMap["type"] = domain.CloudKeystoreTypeAKV.String()
	metadataMap["id"] = id
	metadataMap["name"] = name
	metadataMap["version"] = version

	return metadataMap, nil
}

func getMetadataMapFromMachineIdentityGCM(metadata *domain.CertificateCloudMetadata) (map[string]string, error) {
	metadataMap := make(map[string]string)

	id, err := getCloudIDFromMachineIdentityGCM(metadata)
	if err != nil {
		return nil, err
	}
	name, err := getAttributeFromMachineIdentity(metadata, "name")
	if err != nil {
		return nil, err
	}

	metadataMap["type"] = domain.CloudKeystoreTypeGCM.String()
	metadataMap["id"] = id
	metadataMap["name"] = name

	return metadataMap, nil
}

// excludes everything, except alphanumeric characters, dashes, and underscores
var certificateNameRegex = regexp.MustCompile(`[^a-zA-Z0-9\-]+`)

func normalizeCloudCertificateName(name string) string {
	if name == "" {
		return name
	}
	sanitizedName := certificateNameRegex.ReplaceAllString(strings.ReplaceAll(name, ".", "-"), "")
	return sanitizedName
}

func diffSuppressFuncCloudCertificateName(_ string, oldValue string, newValue string, _ *schema.ResourceData) bool {
	if oldValue == "" {
		return false
	}
	normalizedNewValue := normalizeCloudCertificateName(newValue)

	return oldValue == normalizedNewValue
}
