package venafi

import (
	"context"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

const (
	resourceVenafiCloudKeystoreName = "venafi_cloud_keystore"

	cloudKeystoreResourceName                       = "name"
	cloudKeystoreResourceType                       = "type"
	cloudKeystoreResourceCloudProviderID            = "cloud_provider_id"
	cloudKeystoreResourceCloudProviderName          = "cloud_provider_name"
	cloudKeystoreResourceTeam                       = "team"
	cloudKeystoreResourceACM                        = "acm"
	cloudKeystoreResourceAKV                        = "akv"
	cloudKeystoreResourceGCM                        = "gcm"
	cloudKeystoreResourceDiscoverySchedule          = "discovery_schedule"
	cloudKeystoreResourceIncludeExpired             = "include_expired_certificates"
	cloudKeystoreResourceIncludeRevoked             = "include_revoked_certificates"
	cloudKeystoreResourceMachineIdentitiesCountAttr = "machine_identities_count"

	cloudKeystoreACMRegion       = "region"
	cloudKeystoreACMAccountID    = "account_id"
	cloudKeystoreAKVKeyVaultName = "key_vault_name"
	cloudKeystoreGCMProjectID    = "project_id"
	cloudKeystoreGCMLocation     = "location"
)

// cloudKeystoreConfigBlocks maps each cloud keystore type to the name of its
// configuration block
var cloudKeystoreConfigBlocks = map[string]string{
	domain.CloudKeystoreTypeACMStr: cloudKeystoreResourceACM,
	domain.CloudKeystoreTypeAKVStr: cloudKeystoreResourceAKV,
	domain.CloudKeystoreTypeGCMStr: cloudKeystoreResourceGCM,
}

func resourceVenafiCloudKeystore() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a cloud keystore in CyberArk Certificate Manager, SaaS or Palo Alto Networks Next-Gen Trust Security (NGTS)",
		CreateContext: resourceCloudKeystoreCreate,
		ReadContext:   resourceCloudKeystoreRead,
		UpdateContext: resourceCloudKeystoreUpdate,
		DeleteContext: resourceCloudKeystoreDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
			return validateConfigBlocks("cloud keystore", cloudKeystoreConfigBlocks, d.Get(cloudKeystoreResourceType).(string), func(block string) bool {
				blocks, _ := d.Get(block).([]interface{})
				return len(blocks) > 0
			})
		},
		Schema: map[string]*schema.Schema{
			cloudKeystoreResourceName: {
				Type:        schema.TypeString,
				Description: "Name of the cloud keystore",
				Required:    true,
			},
			cloudKeystoreResourceType: {
				Type:         schema.TypeString,
				Description:  "Type of the cloud keystore: ACM (AWS Certificate Manager), AKV (Azure Key Vault) or GCM (Google Cloud Certificate Manager)",
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{domain.CloudKeystoreTypeACMStr, domain.CloudKeystoreTypeAKVStr, domain.CloudKeystoreTypeGCMStr}, false),
			},
			cloudKeystoreResourceCloudProviderID: {
				Type:        schema.TypeString,
				Description: "ID of the cloud provider the keystore belongs to",
				Required:    true,
				ForceNew:    true,
			},
			cloudKeystoreResourceCloudProviderName: {
				Type:        schema.TypeString,
				Description: "Name of the cloud provider the keystore belongs to",
				Computed:    true,
			},
			cloudKeystoreResourceTeam: {
				Type: schema.TypeString,
				Description: "Name or ID of the team that owns the cloud keystore. Required for CyberArk Certificate Manager, SaaS; " +
					"Palo Alto Networks Next-Gen Trust Security (NGTS) only accepts an ID",
				Optional: true,
			},
			cloudKeystoreResourceACM: {
				Type:        schema.TypeList,
				Description: "Configuration of an AWS Certificate Manager keystore",
				Optional:    true,
				ForceNew:    true,
				MaxItems:    1,
				Elem: &schema.Resource{Schema: map[string]*schema.Schema{
					cloudKeystoreACMRegion: {
						Type:        schema.TypeString,
						Description: "AWS region of the certificate manager",
						Required:    true,
						ForceNew:    true,
					},
					cloudKeystoreACMAccountID: {
						Type:        schema.TypeString,
						Description: "AWS account ID, when it differs from the cloud provider's",
						Optional:    true,
						Computed:    true,
						ForceNew:    true,
					},
				}},
			},
			cloudKeystoreResourceAKV: {
				Type:        schema.TypeList,
				Description: "Configuration of an Azure Key Vault keystore",
				Optional:    true,
				ForceNew:    true,
				MaxItems:    1,
				Elem: &schema.Resource{Schema: map[string]*schema.Schema{
					cloudKeystoreAKVKeyVaultName: {
						Type:        schema.TypeString,
						Description: "Name of the Azure key vault",
						Required:    true,
						ForceNew:    true,
					},
				}},
			},
			cloudKeystoreResourceGCM: {
				Type:        schema.TypeList,
				Description: "Configuration of a Google Cloud Certificate Manager keystore",
				Optional:    true,
				ForceNew:    true,
				MaxItems:    1,
				Elem: &schema.Resource{Schema: map[string]*schema.Schema{
					cloudKeystoreGCMProjectID: {
						Type:        schema.TypeString,
						Description: "GCP project ID",
						Required:    true,
						ForceNew:    true,
					},
					cloudKeystoreGCMLocation: {
						Type:        schema.TypeString,
						Description: "GCP location of the certificate manager, for example \"global\"",
						Required:    true,
						ForceNew:    true,
					},
				}},
			},
			cloudKeystoreResourceDiscoverySchedule: {
				Type:        schema.TypeString,
				Description: "Crontab expression for scheduled certificate discovery, for example \"00 03 * * *\" for every day at 3 AM",
				Optional:    true,
			},
			cloudKeystoreResourceIncludeExpired: {
				Type:        schema.TypeBool,
				Description: "Whether discovery includes expired certificates. Defaults to the platform's setting",
				Optional:    true,
				Computed:    true,
			},
			cloudKeystoreResourceIncludeRevoked: {
				Type:        schema.TypeBool,
				Description: "Whether discovery includes revoked certificates. Defaults to the platform's setting",
				Optional:    true,
				Computed:    true,
			},
			cloudKeystoreResourceMachineIdentitiesCountAttr: {
				Type:        schema.TypeInt,
				Description: "Number of certificates installed in or discovered on the keystore",
				Computed:    true,
			},
		},
	}
}

// configuredBool returns a pointer to the value of a boolean attribute when
// it is set in the configuration, and nil otherwise. Optional+Computed booleans
// cannot be told apart from false with d.GetOk.
func configuredBool(d *schema.ResourceData, key string) *bool {
	config := d.GetRawConfig()
	if config.IsNull() || !config.IsKnown() || !config.Type().IsObjectType() || !config.Type().HasAttribute(key) {
		return nil
	}
	value := config.GetAttr(key)
	if value.IsNull() || !value.IsKnown() || !value.Type().Equals(cty.Bool) {
		return nil
	}
	b := value.True()
	return &b
}

func buildCreateCloudKeystoreRequest(d *schema.ResourceData) domain.CreateCloudKeystoreRequest {
	request := domain.CreateCloudKeystoreRequest{
		Name:            d.Get(cloudKeystoreResourceName).(string),
		Type:            domain.GetCloudKeystoreType(d.Get(cloudKeystoreResourceType).(string)),
		CloudProviderID: d.Get(cloudKeystoreResourceCloudProviderID).(string),
		TeamID:          d.Get(cloudKeystoreResourceTeam).(string),
	}
	if acm := singleBlock(d, cloudKeystoreResourceACM); acm != nil {
		request.ACM = &domain.CloudKeystoreACMConfiguration{
			Region:    acm[cloudKeystoreACMRegion].(string),
			AccountID: acm[cloudKeystoreACMAccountID].(string),
		}
	}
	if akv := singleBlock(d, cloudKeystoreResourceAKV); akv != nil {
		request.AKV = &domain.CloudKeystoreAKVConfiguration{KeyVaultName: akv[cloudKeystoreAKVKeyVaultName].(string)}
	}
	if gcm := singleBlock(d, cloudKeystoreResourceGCM); gcm != nil {
		request.GCM = &domain.CloudKeystoreGCMConfiguration{
			ProjectID: gcm[cloudKeystoreGCMProjectID].(string),
			Location:  gcm[cloudKeystoreGCMLocation].(string),
		}
	}

	discovery := &domain.CloudDiscoveryOptions{
		ScheduleSpecification:      optionalString(d.Get(cloudKeystoreResourceDiscoverySchedule).(string)),
		IncludeExpiredCertificates: configuredBool(d, cloudKeystoreResourceIncludeExpired),
		IncludeRevokedCertificates: configuredBool(d, cloudKeystoreResourceIncludeRevoked),
	}
	if discovery.ScheduleSpecification != nil || discovery.IncludeExpiredCertificates != nil || discovery.IncludeRevokedCertificates != nil {
		request.Discovery = discovery
	}
	return request
}

// buildUpdateCloudKeystoreRequest returns the changes to apply, or nil when
// none of the updatable attributes changed
func buildUpdateCloudKeystoreRequest(d *schema.ResourceData) *domain.UpdateCloudKeystoreRequest {
	request := &domain.UpdateCloudKeystoreRequest{ID: d.Id()}
	changed := false

	if d.HasChange(cloudKeystoreResourceName) {
		name := d.Get(cloudKeystoreResourceName).(string)
		request.Name = &name
		changed = true
	}
	if d.HasChange(cloudKeystoreResourceTeam) {
		if team := d.Get(cloudKeystoreResourceTeam).(string); team != "" {
			request.TeamID = &team
			changed = true
		}
	}

	discovery := &domain.CloudDiscoveryOptions{}
	if d.HasChange(cloudKeystoreResourceDiscoverySchedule) {
		// an empty value clears the schedule
		schedule := d.Get(cloudKeystoreResourceDiscoverySchedule).(string)
		discovery.ScheduleSpecification = &schedule
	}
	if d.HasChange(cloudKeystoreResourceIncludeExpired) {
		discovery.IncludeExpiredCertificates = configuredBool(d, cloudKeystoreResourceIncludeExpired)
	}
	if d.HasChange(cloudKeystoreResourceIncludeRevoked) {
		discovery.IncludeRevokedCertificates = configuredBool(d, cloudKeystoreResourceIncludeRevoked)
	}
	if discovery.ScheduleSpecification != nil || discovery.IncludeExpiredCertificates != nil || discovery.IncludeRevokedCertificates != nil {
		request.Discovery = discovery
		changed = true
	}

	if !changed {
		return nil
	}
	return request
}

func storeCloudKeystoreInState(keystore *domain.CloudKeystore, d *schema.ResourceData) error {
	d.SetId(keystore.ID)
	values := map[string]interface{}{
		cloudKeystoreResourceName:                       keystore.Name,
		cloudKeystoreResourceType:                       keystore.Type.String(),
		cloudKeystoreResourceCloudProviderName:          keystore.CloudProviderName,
		cloudKeystoreResourceMachineIdentitiesCountAttr: keystore.MachineIdentitiesCount,
	}
	if keystore.CloudProviderID != "" {
		values[cloudKeystoreResourceCloudProviderID] = keystore.CloudProviderID
	}
	if keystore.ACM != nil {
		values[cloudKeystoreResourceACM] = []interface{}{map[string]interface{}{
			cloudKeystoreACMRegion:    keystore.ACM.Region,
			cloudKeystoreACMAccountID: keystore.ACM.AccountID,
		}}
	}
	if keystore.AKV != nil {
		values[cloudKeystoreResourceAKV] = []interface{}{map[string]interface{}{
			cloudKeystoreAKVKeyVaultName: keystore.AKV.KeyVaultName,
		}}
	}
	if keystore.GCM != nil {
		values[cloudKeystoreResourceGCM] = []interface{}{map[string]interface{}{
			cloudKeystoreGCMProjectID: keystore.GCM.ProjectID,
			cloudKeystoreGCMLocation:  keystore.GCM.Location,
		}}
	}
	if keystore.DiscoveryConfiguration != nil {
		values[cloudKeystoreResourceDiscoverySchedule] = keystore.DiscoveryConfiguration.ScheduleSpecification
		values[cloudKeystoreResourceIncludeExpired] = keystore.DiscoveryConfiguration.IncludeExpiredCertificates
		values[cloudKeystoreResourceIncludeRevoked] = keystore.DiscoveryConfiguration.IncludeRevokedCertificates
	}
	return setAll(d, values)
}

func resourceCloudKeystoreCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	request := buildCreateCloudKeystoreRequest(d)
	logFields := map[string]interface{}{
		cloudKeystoreResourceName:            request.Name,
		cloudKeystoreResourceType:            request.Type.String(),
		cloudKeystoreResourceCloudProviderID: request.CloudProviderID,
	}
	tflog.Info(ctx, "creating cloud keystore", logFields)

	manager, _, err := getCloudKeystoreManager(ctx, meta, resourceVenafiCloudKeystoreName)
	if err != nil {
		return diag.FromErr(err)
	}

	keystore, err := manager.CreateCloudKeystore(request)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := storeCloudKeystoreInState(keystore, d); err != nil {
		return diag.FromErr(err)
	}

	logFields["id"] = keystore.ID
	tflog.Info(ctx, "cloud keystore created", logFields)
	return nil
}

func resourceCloudKeystoreRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	logFields := map[string]interface{}{"id": d.Id()}
	tflog.Info(ctx, "reading cloud keystore", logFields)

	manager, _, err := getCloudKeystoreManager(ctx, meta, resourceVenafiCloudKeystoreName)
	if err != nil {
		return diag.FromErr(err)
	}

	keystore, err := findCloudKeystoreByID(manager, d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	if keystore == nil {
		tflog.Info(ctx, "cloud keystore not found, removing it from state", logFields)
		d.SetId("")
		return nil
	}

	if err := storeCloudKeystoreInState(keystore, d); err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "cloud keystore read", logFields)
	return nil
}

func resourceCloudKeystoreUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	logFields := map[string]interface{}{"id": d.Id()}
	tflog.Info(ctx, "updating cloud keystore", logFields)

	request := buildUpdateCloudKeystoreRequest(d)
	if request == nil {
		return resourceCloudKeystoreRead(ctx, d, meta)
	}

	manager, _, err := getCloudKeystoreManager(ctx, meta, resourceVenafiCloudKeystoreName)
	if err != nil {
		return diag.FromErr(err)
	}

	keystore, err := manager.UpdateCloudKeystore(*request)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := storeCloudKeystoreInState(keystore, d); err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "cloud keystore updated", logFields)
	return nil
}

func resourceCloudKeystoreDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	logFields := map[string]interface{}{"id": d.Id()}
	tflog.Info(ctx, "deleting cloud keystore", logFields)

	manager, _, err := getCloudKeystoreManager(ctx, meta, resourceVenafiCloudKeystoreName)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := manager.DeleteCloudKeystore(d.Id()); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	tflog.Info(ctx, "cloud keystore deleted", logFields)
	return nil
}
