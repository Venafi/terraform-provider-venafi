package venafi

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

const (
	resourceVenafiCloudProviderValidationName = "venafi_cloud_provider_validation"

	cloudProviderValidationCloudProviderID = "cloud_provider_id"
	cloudProviderValidationTriggers        = "triggers"
	cloudProviderValidationStatus          = "status"

	cloudProviderValidationDefaultTimeout = 5 * time.Minute
)

// cloudProviderValidationRetryInterval is the wait between validation attempts.
// It is a variable so that tests can shorten it.
var cloudProviderValidationRetryInterval = 15 * time.Second

func resourceVenafiCloudProviderValidation() *schema.Resource {
	return &schema.Resource{
		Description: "Validates a cloud provider, which is required before cloud keystores can use it. " +
			"Validation is retried until it succeeds or the create timeout expires, since cloud IAM changes take time to propagate.",
		CreateContext: resourceCloudProviderValidationCreate,
		ReadContext:   resourceCloudProviderValidationRead,
		DeleteContext: resourceCloudProviderValidationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceCloudProviderValidationImport,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(cloudProviderValidationDefaultTimeout),
		},
		Schema: map[string]*schema.Schema{
			cloudProviderValidationCloudProviderID: {
				Type:        schema.TypeString,
				Description: "ID of the cloud provider to validate",
				Required:    true,
				ForceNew:    true,
			},
			cloudProviderValidationTriggers: {
				Type:        schema.TypeMap,
				Description: "Arbitrary values that cause the cloud provider to be validated again when they change",
				Optional:    true,
				ForceNew:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			cloudProviderValidationStatus: {
				Type:        schema.TypeString,
				Description: "Validation status of the cloud provider",
				Computed:    true,
			},
		},
	}
}

func resourceCloudProviderValidationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerID := d.Get(cloudProviderValidationCloudProviderID).(string)
	logFields := map[string]interface{}{cloudProviderValidationCloudProviderID: providerID}
	tflog.Info(ctx, "validating cloud provider", logFields)

	manager, _, err := getCloudProviderManager(ctx, meta, resourceVenafiCloudProviderValidationName)
	if err != nil {
		return diag.FromErr(err)
	}

	timeout := d.Timeout(schema.TimeoutCreate)
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		// The API reports a failed validation as NOT_VALIDATED with the reason
		// in the details, rather than as an error. Errors are request failures.
		result, err := manager.ValidateCloudProvider(providerID)
		if err != nil {
			return diag.FromErr(err)
		}
		if result.Status == domain.CloudProviderStatusValidated {
			break
		}

		logFields["attempt"] = attempt
		logFields["details"] = result.Details
		tflog.Info(ctx, "cloud provider not validated yet", logFields)

		// Nothing is stored in state on failure, so the next apply validates
		// again. The SDK cancels ctx at the create timeout too; report the
		// platform's reason either way rather than a bare context error.
		notValidated := diag.Errorf("cloud provider %s was not validated within %s: %s", providerID, timeout, result.Details)
		if time.Now().Add(cloudProviderValidationRetryInterval).After(deadline) {
			return notValidated
		}
		select {
		case <-ctx.Done():
			return notValidated
		case <-time.After(cloudProviderValidationRetryInterval):
		}
	}

	d.SetId(providerID)
	if err := d.Set(cloudProviderValidationStatus, domain.CloudProviderStatusValidated.String()); err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "cloud provider validated", logFields)
	return nil
}

func resourceCloudProviderValidationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerID := d.Get(cloudProviderValidationCloudProviderID).(string)
	logFields := map[string]interface{}{cloudProviderValidationCloudProviderID: providerID}
	tflog.Info(ctx, "reading cloud provider validation", logFields)

	manager, _, err := getCloudProviderManager(ctx, meta, resourceVenafiCloudProviderValidationName)
	if err != nil {
		return diag.FromErr(err)
	}

	provider, err := findCloudProviderByID(manager, providerID)
	if err != nil {
		return diag.FromErr(err)
	}
	// The status goes back to NOT_VALIDATED when the provider's configuration
	// changes or a later validation fails. Removing the validation from state
	// makes the next plan validate the provider again.
	if provider == nil || provider.Status != domain.CloudProviderStatusValidated {
		tflog.Info(ctx, "cloud provider is no longer validated, removing the validation from state", logFields)
		d.SetId("")
		return nil
	}

	if err := d.Set(cloudProviderValidationStatus, provider.Status.String()); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceCloudProviderValidationDelete(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// There is nothing to undo on the platform
	tflog.Info(ctx, "removing cloud provider validation from state", map[string]interface{}{"id": d.Id()})
	d.SetId("")
	return nil
}

func resourceCloudProviderValidationImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	if d.Id() == "" {
		return nil, fmt.Errorf("cloud provider ID is empty")
	}
	if err := d.Set(cloudProviderValidationCloudProviderID, d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
