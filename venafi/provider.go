package venafi

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

// Provider returns a terraform.ResourceProvider.
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_key": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_API", nil),
				Description: "Your Venafi SaaS API Key.",
			},

			"zone": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_ZONE", "Default"),
				Description: "The user password for vcd API operations.",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"venafi_csr":         resourceVenafiCSR(),
			"venafi_certificate": resourceVenafiCertificate(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		APIKey: d.Get("api_key").(string),
		Zone:   d.Get("zone").(string),
	}

	client := config.Client()
	return client, nil
}
