package venafi

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strings"
)

const (
	messageVenafiPingFailed       = "Failed to ping Venafi endpoint: "
	messageVenafiPingSuccessful   = "Venafi ping successful"
	messageVenafiClientInitFailed = "Failed to initialize Venafi client"
	messageVenafiConfigFailed     = "Failed to build config for Venafi issuer: "
	messageUseDevMode             = "Using dev mode to issue certificate"
	messageUseVaas                = "Using VaaS to issue certificate"

	utilityName = "HashiCorp Terraform"
)

// Provider returns a terraform.ResourceProvider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_URL", nil),
				Description: `The Venafi Web Service URL.. Example: https://tpp.venafi.example/vedsdk`,
			},
			"zone": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_ZONE", "Default"),
				Description: `DN of the Venafi Platform policy folder or name of the Venafi as a Service application. 
Example for Platform: testpolicy\\vault
Example for Venafi as a Service: Default`,
			},
			"tpp_username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_USER", nil),
				Description: `WebSDK user for Venafi Platform. Example: admin`,
				Deprecated:  ", please use access_token instead",
			},
			"tpp_password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_PASS", nil),
				Description: `Password for WebSDK user. Example: password`,
				Deprecated:  ", please use access_token instead",
			},
			"access_token": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_TOKEN", nil),
				Description: `Access token for TPP, user should use this for authentication`,
			},
			"refresh_token": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_REFRESH_TOKEN", nil),
				Description: `Refresh token for TPP, user should use this for authentication`,
			},
			"client_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_CLIENT_ID", nil),
				Description: `Client Id for Refresh token based authentication. Default value: "vcert-sdk"`,
			},
			"api_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_API", nil),
				Description: `API key for Venafi as a Service. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
			},
			"trust_bundle": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Description: `Use to specify a PEM-formatted file that contains certificates to be trust anchors for all communications with the Venafi Web Service.
Example:
  trust_bundle = "${file("chain.pem")}"`,
			},
			"dev_mode": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_DEVMODE", nil),
				Description: `When set to true, the resulting certificate will be issued by an ephemeral, no trust CA rather than enrolling using Venafi as a Service or Trust Protection Platform. Useful for development and testing.`,
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"venafi_certificate":     resourceVenafiCertificate(),
			"venafi_policy":          resourceVenafiPolicy(),
			"venafi_ssh_certificate": resourceVenafiSshCertificate(),
			"venafi_ssh_config":      resourceVenafiSshConfig(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {

	tflog.Info(ctx, "Configuring provider\n")
	apiKey := d.Get("api_key").(string)
	url := d.Get("url").(string)
	tppUser := d.Get("tpp_username").(string)
	tppPassword := d.Get("tpp_password").(string)
	accessToken := d.Get("access_token").(string)
	refreshToken := d.Get("refresh_token").(string)
	clientId := d.Get("client_id").(string)
	zone := d.Get("zone").(string)
	tflog.Info(ctx, fmt.Sprintf("====ZONE==== : %s", zone))
	devMode := d.Get("dev_mode").(bool)
	trustBundle := d.Get("trust_bundle").(string)

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	var cfg vcert.Config

	zone = normalizeZone(zone)

	if devMode {
		tflog.Info(ctx, messageUseDevMode)
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeFake,
			LogVerbose:    true,
		}
	} else if tppUser != "" && tppPassword != "" && accessToken == "" {
		tflog.Info(ctx, fmt.Sprintf("Using Platform with url %s to issue certificate\n", url))
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       url,
			Credentials: &endpoint.Authentication{
				User:     tppUser,
				Password: tppPassword,
			},
			Zone:       zone,
			LogVerbose: true,
		}
	} else if accessToken != "" {
		tflog.Info(ctx, fmt.Sprintf("Using Platform with url %s to issue certificate\n", url))
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       url,
			Credentials: &endpoint.Authentication{
				AccessToken: accessToken,
			},
			Zone:       zone,
			LogVerbose: true,
		}
	} else if refreshToken != "" {
		tflog.Info(ctx, fmt.Sprintf("Using Platform with url %s to issue certificate\n", url))
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       url,
			Credentials: &endpoint.Authentication{
				RefreshToken: refreshToken,
				ClientId: clientId
			},
			Zone:       zone,
			LogVerbose: true,
		}	
	} else if apiKey != "" {
		if url != "" {
			tflog.Info(ctx, messageUseVaas)
			cfg = vcert.Config{
				ConnectorType: endpoint.ConnectorTypeCloud,
				BaseUrl:       url,
				Credentials: &endpoint.Authentication{
					APIKey: apiKey,
				},
				Zone:       zone,
				LogVerbose: true,
			}
		} else {
			tflog.Info(ctx, messageUseVaas)
			cfg = vcert.Config{
				ConnectorType: endpoint.ConnectorTypeCloud,
				Credentials: &endpoint.Authentication{
					APIKey: apiKey,
				},
				Zone:       zone,
				LogVerbose: true,
			}
		}
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiConfigFailed,
		})
		return nil, diags
	}

	if trustBundle != "" {
		tflog.Info(ctx, fmt.Sprintf("Importing trusted certificate: \n %s", trustBundle))
		cfg.ConnectionTrust = trustBundle
	}
	cl, err := vcert.NewClient(&cfg)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiConfigFailed + ": " + err.Error(),
		})
		return nil, diags
	}
	err = cl.Ping()
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiPingFailed,
			Detail:   messageVenafiConfigFailed + ": " + err.Error(),
		})
		return nil, diags
	}

	return &cfg, diags
}

func normalizeZone(zone string) string {
	if zone == "" {
		return zone
	}

	values := strings.Split(zone, "\\")
	newZone := ""
	for i, z := range values {
		if len(z) > 0 {
			newZone += z

			if i < len(values)-1 {
				newZone += "\\"
			}
		}
	}
	//Add leading forward slash when the zone includes the "VED" prefix
	if strings.HasPrefix(newZone, "VED") {
		newZone = "\\" + newZone
	}

	log.Printf("[INFO] Normalized zone : %s", newZone)
	return newZone
}
