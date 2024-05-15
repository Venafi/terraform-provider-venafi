package venafi

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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
	connector, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	if connector.GetType() != endpoint.ConnectorTypeCloud {
		return buildStandardDiagError(fmt.Sprintf("venafi platform detected as [%s]. Cloud Provider Data source is only available for VCP", connector.GetType().String()))
	}

	cpName := d.Get(cloudProviderName)
	if cpName == nil {
		return buildStandardDiagError("cloud provider name not provided")
	}

	tflog.Info(ctx, "reading cloud provider", map[string]interface{}{"name": cpName})
	cpObject, err := connector.(*cloud.Connector).GetCloudProviderByName(cpName.(string))
	if err != nil {
		return diag.FromErr(err)
	}

	tflog.Debug(ctx, "cloud provider details", map[string]interface{}{
		"id":              cpObject.ID,
		"name":            cpObject.Name,
		"type":            cpObject.Type,
		"status":          cpObject.Status,
		"status_details":  cpObject.StatusDetails,
		"keystores_count": cpObject.KeystoresCount,
	})

	d.SetId(cpObject.ID)

	err = d.Set(cloudProviderType, cpObject.Type)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderStatus, cpObject.Status)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderStatusDetails, cpObject.StatusDetails)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudProviderKeystoresCount, cpObject.KeystoresCount)
	if err != nil {
		return diag.FromErr(err)
	}

	tflog.Info(ctx, "cloud provider found", map[string]interface{}{"name": cpName})
	return nil
}
