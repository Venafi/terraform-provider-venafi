package venafi

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
)

const (
	cloudProviderName           = "name"
	cloudProviderType           = "type"
	cloudProviderStatus         = "status"
	cloudProviderStatusDetails  = "status_details"
	cloudProviderKeystoresCount = "keystores_count"
)

func DataSourceCloudProvider() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceCloudProviderRead,
		Schema: map[string]*schema.Schema{
			cloudProviderName: {
				Type:        schema.TypeString,
				Description: "Name of the Cloud Provider to look for",
				Required:    true,
				ForceNew:    true,
			},
			cloudProviderType: {
				Type:        schema.TypeString,
				Description: "Type of the Cloud Provider",
				Computed:    true,
			},
			cloudProviderStatus: {
				Type:        schema.TypeString,
				Description: "Status of the Cloud Provider",
				Computed:    true,
			},
			cloudProviderStatusDetails: {
				Type:        schema.TypeString,
				Description: "Details of the Cloud Provider status, if any",
				Computed:    true,
			},
			cloudProviderKeystoresCount: {
				Type:        schema.TypeInt,
				Description: "Number of keystores associated with the Cloud Provider",
				Computed:    true,
			},
		},
	}
}

func dataSourceCloudProviderRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cpName := d.Get(cloudProviderName)
	tflog.Info(ctx, "reading cloud provider", map[string]interface{}{
		cloudProviderName: cpName,
	})

	connector, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	if connector.GetType() != endpoint.ConnectorTypeCloud {
		return buildStandardDiagError(fmt.Sprintf("cyberark platform detected as [%s]. Cloud Provider data source is only available for CyberArk Certificate Manager, SaaS", connector.GetType().String()))
	}

	cloudProvider, err := connector.(*cloud.Connector).GetCloudProvider(domain.GetCloudProviderRequest{
		Name: cpName.(string),
	})
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, "successfully retrieved cloud provider from CyberArk Certificate Manager, SaaS API", map[string]interface{}{
		cloudProviderName: cpName,
	})

	d.SetId(cloudProvider.ID)
	err = d.Set(cloudProviderType, cloudProvider.Type.String())
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderStatus, cloudProvider.Status.String())
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderStatusDetails, cloudProvider.StatusDetails)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderKeystoresCount, cloudProvider.KeystoresCount)
	if err != nil {
		return diag.FromErr(err)
	}

	tflog.Info(ctx, "cloud provider stored in state", map[string]interface{}{
		cloudProviderName: cpName,
	})
	return nil
}
