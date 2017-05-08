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
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_API", nil),
				Description: "Your Venafi Cloud API Key.",
			},

			"url": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_URL", nil),
				Description: "The Venafi Web Service URL.",
			},

			"tpp_username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_USER", nil),
				Description: "Your Venafi Trust Protection Platform WebSDK Username.",
			},

			"tpp_password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_PASS", nil),
				Description: "Your Venafi Trust Protection Platform WebSDK Password.",
			},

			"zone": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_ZONE", "Default"),
				Description: "The policy zone for certificate enrollment.",
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
		URL:	d.Get("url").(string),
		Username: d.Get("tpp_username").(string),
		Password: d.Get("tpp_password").(string),
		Zone:   d.Get("zone").(string),
	}

	client := config.Client()
	return client, nil
}
