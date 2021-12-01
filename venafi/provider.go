package venafi

import (
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"log"
	"strings"
)

const (
	messageVenafiPingFailed       = "Failed to ping Venafi endpoint: "
	messageVenafiPingSucessfull   = "Venafi ping sucessfull"
	messageVenafiClientInitFailed = "Failed to initialize Venafi client: "
	messageVenafiConfigFailed     = "Failed to build config for Venafi issuer: "
	messageUseDevMode             = "Using dev mode to issue certificate"
	messageUseCloud               = "Using Cloud to issue certificate"

	utilityName = "HashiCorp Terraform"
)

// Provider returns a terraform.ResourceProvider.
func Provider() terraform.ResourceProvider {
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
				Description: `DN of the Venafi Platform policy folder or name of the Venafi Cloud zone. 
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: Default`,
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
			"api_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VENAFI_API", nil),
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
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
				Description: `When set to true, the resulting certificate will be issued by an ephemeral, no trust CA rather than enrolling using Venafi Cloud or Platform. Useful for development and testing.`,
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"venafi_certificate":     resourceVenafiCertificate(),
			"venafi_policy":          resourceVenafiPolicy(),
			"venafi_ssh_certificate": resourceVenafiSshCertificate(),
			"venafi_ssh_config":      resourceVenafiSshConfig(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {

	log.Printf("Configuring provider\n")
	apiKey := d.Get("api_key").(string)
	url := d.Get("url").(string)
	tppUser := d.Get("tpp_username").(string)
	tppPassword := d.Get("tpp_password").(string)
	accessToken := d.Get("access_token").(string)
	zone := d.Get("zone").(string)
	log.Printf("====ZONE==== : %s", zone)
	devMode := d.Get("dev_mode").(bool)
	trustBundle := d.Get("trust_bundle").(string)

	var cfg vcert.Config

	zone = normalizeZone(zone)

	if devMode {
		log.Print(messageUseDevMode)
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeFake,
			LogVerbose:    true,
		}
	} else if tppUser != "" && tppPassword != "" && accessToken == "" {
		log.Printf("Using Platform with url %s to issue certificate\n", url)
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
		log.Printf("Using Platform with url %s to issue certificate\n", url)
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       url,
			Credentials: &endpoint.Authentication{
				AccessToken: accessToken,
			},
			Zone:       zone,
			LogVerbose: true,
		}
	} else if url != "" && accessToken == "" {
		log.Printf("Using Platform with url %s to get ssh config\n", url)
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       url,
			Credentials: &endpoint.Authentication{
				AccessToken: accessToken,
			},
			Zone:       zone,
			LogVerbose: true,
		}
		log.Printf("Success created config\n")
	} else if apiKey != "" {
		if url != "" {
			log.Println(messageUseCloud)
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
			log.Println(messageUseCloud)
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
		return nil, fmt.Errorf(messageVenafiConfigFailed)
	}

	if trustBundle != "" {
		log.Printf("Importing trusted certificate: \n %s", trustBundle)
		cfg.ConnectionTrust = trustBundle
	}
	cl, err := vcert.NewClient(&cfg)
	// We only ignore the errors from VCert if we are getting the SSH config without the Principals from TPP
	if err != nil {
		strErr := (err).Error()
		if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: missing credentials" {
			log.Printf("Unable to build connector for %s: %s", cl.GetType(), err)
		} else if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: can't determine valid credentials set" {
			log.Printf("Unable to build connector for %s: %s", cl.GetType(), err)
		} else {
			log.Printf("Successfully built connector for %s", cl.GetType())
		}
	} else {
		log.Printf("Successfully built connector for %s", cl.GetType())
	}

	err = cl.Ping()
	if err != nil {
		log.Printf(messageVenafiPingFailed + err.Error())
		return nil, err
	}

	return &cfg, nil
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

	log.Printf("Normalized zone : %s", newZone)
	return newZone
}
