package venafi

import (
	"context"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/ngts"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	cloudKeystoreProviderID             = "cloud_provider_id"
	cloudKeystoreName                   = "name"
	cloudKeystoreType                   = "type"
	cloudKeystoreMachineIdentitiesCount = "machine_identities_count"
)

func DataSourceCloudKeystore() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceCloudKeystoreRead,
		Schema: map[string]*schema.Schema{
			cloudKeystoreProviderID: {
				Type:        schema.TypeString,
				Description: "ID of the parent Cloud Provider the keystore belongs to",
				Required:    true,
				ForceNew:    true,
			},
			cloudKeystoreName: {
				Type:        schema.TypeString,
				Description: "Name of the Cloud Keystore to look for",
				Required:    true,
				ForceNew:    true,
			},
			cloudKeystoreType: {
				Type:        schema.TypeString,
				Description: "Type of the Cloud Keystore",
				Computed:    true,
			},
			cloudKeystoreMachineIdentitiesCount: {
				Type:        schema.TypeInt,
				Description: "Number of machine identities associated with the Cloud Keystore",
				Computed:    true,
			},
		},
	}
}

func dataSourceCloudKeystoreRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerID := d.Get(cloudKeystoreProviderID).(string)
	keystoreName := d.Get(cloudKeystoreName).(string)
	tflog.Info(ctx, "reading cloud keystore", map[string]interface{}{
		cloudKeystoreProviderID: providerID,
		cloudKeystoreName:       keystoreName,
	})

	connector, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	if !(connector.GetType() == endpoint.ConnectorTypeCloud || connector.GetType() == endpoint.ConnectorTypeNGTS) {
		return buildStandardDiagError(fmt.Sprintf("Platform detected as [%s]. Cloud Keystore data source is only available for %s or %s", connector.GetType(), endpoint.ConnectorTypeCloud, endpoint.ConnectorTypeNGTS))
	}

	var keystore *domain.CloudKeystore
	switch conn := connector.(type) {
	case *cloud.Connector:
		keystore, err = conn.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudProviderID:   &providerID,
			CloudKeystoreName: &keystoreName,
		})
	case *ngts.Connector:
		keystore, err = conn.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudProviderID:   &providerID,
			CloudKeystoreName: &keystoreName,
		})
	default:
		return buildStandardDiagError(fmt.Sprintf("connector type not supported %s", connector.GetType()))
	}
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, fmt.Sprintf("successfully retrieved cloud keystore from %s", connector.GetType()), map[string]interface{}{
		cloudKeystoreProviderID: providerID,
		cloudKeystoreName:       keystoreName,
	})

	d.SetId(keystore.ID)
	err = d.Set(cloudKeystoreType, keystore.Type.String())
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(cloudKeystoreMachineIdentitiesCount, keystore.MachineIdentitiesCount)
	if err != nil {
		return diag.FromErr(err)
	}

	tflog.Info(ctx, "cloud keystore stored in state", map[string]interface{}{
		cloudKeystoreProviderID: providerID,
		cloudKeystoreName:       keystoreName,
	})
	return nil
}
