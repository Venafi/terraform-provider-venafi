package venafi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/pkcs12"
)

const (
	messageVenafiPingFailed                  = "Failed to ping Venafi endpoint"
	messageVenafiPingSuccessful              = "Venafi ping successful"
	messageVenafiClientInitFailed            = "Failed to initialize Venafi client"
	messageVenafiProviderConfigCastingFailed = "Failed to retrieve Venafi Provider Configuration from context/meta"
	messageVenafiConfigFailed                = "Failed to build config for Venafi issuer"
	messageUseDevMode                        = "Using dev mode to issue certificate"
	messageUseVaas                           = "Using VaaS to issue certificate"
	messageUseTLSPDC                         = "Using Platform TLSPDC with url %s to issue certificate"
	messageVenafiAuthFailed                  = "Failed to authenticate to Venafi platform"

	utilityName           = "HashiCorp Terraform"
	defaultClientID       = "hashicorp-terraform-by-venafi"
	defaultSkipRetirement = false

	// Environment variables for Provider attributes
	envVenafiURL            = "VENAFI_URL"
	envVenafiZone           = "VENAFI_ZONE"
	envVenafiUsername       = "VENAFI_USER"
	envVenafiPassword       = "VENAFI_PASS"
	envVenafiAccessToken    = "VENAFI_TOKEN"
	envVenafiApiKey         = "VENAFI_API"
	envVenafiDevMode        = "VENAFI_DEVMODE"
	envVenafiP12Certificate = "VENAFI_P12_CERTIFICATE"
	envVenafiP12Password    = "VENAFI_P12_PASSWORD"
	envVenafiClientID       = "VENAFI_CLIENT_ID"
	envVenafiSkipRetirement = "VENAFI_SKIP_RETIREMENT"

	// Attributes of the provider
	providerURL            = "url"
	providerZone           = "zone"
	providerDevMode        = "dev_mode"
	providerUsername       = "tpp_username"
	providerPassword       = "tpp_password"
	providerP12Cert        = "p12_cert_filename"
	providerP12Password    = "p12_cert_password"
	providerAccessToken    = "access_token"
	providerApiKey         = "api_key"
	providerTrustBundle    = "trust_bundle"
	providerClientID       = "client_id"
	providerSkipRetirement = "skip_retirement"
)

var (
	messageVenafiNoAuthProvided = fmt.Sprintf("no authorization attributes defined in provider. "+
		"One of the following must be set: %s, %s/%s, %s/%s, or %s",
		providerAccessToken, providerP12Cert, providerP12Password, providerUsername, providerPassword, providerApiKey)
)

// Provider returns a terraform.ResourceProvider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			providerURL: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiURL, nil),
				Description: "The Venafi Platform URL. Example: https://tpp.venafi.example/vedsdk",
			},
			providerZone: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiZone, "Default"),
				Description: `DN of the Venafi TLSPDC policy folder or name of the Venafi as a Service application plus issuing template alias. 
Example for Platform: testPolicy\\vault
Example for Venafi as a Service: myApp\\Default`,
			},
			providerUsername: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiUsername, nil),
				Description: "WebSDK user for Venafi TLSPDC. Example: admin",
				Deprecated:  ", please use access_token instead",
			},
			providerPassword: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiPassword, nil),
				Description: "Password for WebSDK user. Example: password",
				Deprecated:  ", please use access_token instead",
				Sensitive:   true,
			},
			providerAccessToken: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiAccessToken, nil),
				Description: "Access token for Venafi TLSPDC, user should use this for authentication",
				Sensitive:   true,
			},
			providerP12Cert: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiP12Certificate, nil),
				Description: "Filename of PKCS#12 keystore containing a client certificate, private key, and chain certificates to authenticate to TLSPDC",
			},
			providerP12Password: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiP12Password, nil),
				Description: "Password for the PKCS#12 keystore declared in p12_cert",
				Sensitive:   true,
			},
			providerTrustBundle: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Use to specify a PEM-formatted file that contains certificates to be trust anchors for all communications with the Venafi Web Service.
Example:
  trust_bundle = "${file("chain.pem")}"`,
			},
			providerApiKey: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiApiKey, nil),
				Description: `API key for Venafi as a Service. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
				Sensitive:   true,
			},
			providerDevMode: {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiDevMode, nil),
				Description: `When set to true, the resulting certificate will be issued by an ephemeral, no trust CA rather than enrolling using Venafi as a Service or Trust Protection Platform. Useful for development and testing.`,
			},
			providerClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiClientID, defaultClientID),
				Description: "application that will be using the token",
			},
			providerSkipRetirement: {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiSkipRetirement, defaultSkipRetirement),
				Description: `When true, certificates will not be retired on Venafi platforms when terraform destroy is run. Default is false.`,
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

type venafiProviderConfig struct {
	vCertCfg       *vcert.Config
	skipRetirement bool
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {

	tflog.Info(ctx, "Configuring venafi provider")
	apiKey := d.Get(providerApiKey).(string)
	url := d.Get(providerURL).(string)
	tppUser := d.Get(providerUsername).(string)
	tppPassword := d.Get(providerPassword).(string)
	accessToken := d.Get(providerAccessToken).(string)
	zone := d.Get(providerZone).(string)
	trustBundle := d.Get(providerTrustBundle).(string)
	p12Certificate := d.Get(providerP12Cert).(string)
	p12Password := d.Get(providerP12Password).(string)
	clientID := d.Get(providerClientID).(string)
	skipRetirement := d.Get(providerSkipRetirement).(bool)

	// Normalize zone for VCert usage
	zone = normalizeZone(zone)

	//Dev Mode
	devMode := d.Get(providerDevMode).(bool)
	// TLSPDC auth methods
	userPassMethod := tppUser != "" && tppPassword != ""
	clientCertMethod := p12Certificate != "" && p12Password != ""
	accessTokenMethod := accessToken != ""
	// TLSPC auth methods
	apiKeyMethod := apiKey != ""

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	if !accessTokenMethod && !clientCertMethod && !userPassMethod && !apiKeyMethod && !devMode {
		tflog.Error(ctx, messageVenafiNoAuthProvided)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   fmt.Sprintf("%s: %s", messageVenafiConfigFailed, messageVenafiNoAuthProvided),
		})
		return nil, diags
	}

	cfg := vcert.Config{
		BaseUrl:    url,
		Zone:       zone,
		LogVerbose: true,
		Credentials: &endpoint.Authentication{
			ClientId: clientID,
		},
	}

	if devMode {
		tflog.Info(ctx, messageUseDevMode)
		cfg.ConnectorType = endpoint.ConnectorTypeFake

	} else if accessTokenMethod {
		tflog.Info(ctx, fmt.Sprintf(messageUseTLSPDC, url))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.AccessToken = accessToken

	} else if clientCertMethod {
		tflog.Info(ctx, fmt.Sprintf(messageUseTLSPDC, url))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.ClientPKCS12 = true

		err := setTLSConfig(ctx, p12Certificate, p12Password)
		if err != nil {
			tflog.Error(ctx, err.Error())
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  messageVenafiClientInitFailed,
				Detail:   fmt.Sprintf("%s: %s", messageVenafiConfigFailed, err.Error()),
			})
			return nil, diags
		}

	} else if userPassMethod {
		tflog.Info(ctx, fmt.Sprintf(messageUseTLSPDC, url))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.User = tppUser
		cfg.Credentials.Password = tppPassword

	} else if apiKeyMethod {
		tflog.Info(ctx, messageUseVaas)
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.Credentials.APIKey = apiKey

	} else {
		tflog.Error(ctx, messageVenafiNoAuthProvided)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   fmt.Sprintf("%s: %s", messageVenafiConfigFailed, messageVenafiNoAuthProvided),
		})
		return nil, diags
	}

	if trustBundle != "" {
		tflog.Info(ctx, "Using trusted certificate")
		tflog.Debug(ctx, fmt.Sprintf("Using trusted certificate: \n %s", trustBundle))
		cfg.ConnectionTrust = trustBundle
	}

	err := pingVenafi(ctx, &cfg)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiPingFailed + ": " + err.Error(),
		})
		return nil, diags
	}

	if clientCertMethod {
		err = getAccessTokenFromClientCertificate(ctx, &cfg)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  messageVenafiClientInitFailed,
				Detail:   messageVenafiAuthFailed + ": " + err.Error(),
			})
		}
	}

	return &venafiProviderConfig{
		vCertCfg:       &cfg,
		skipRetirement: skipRetirement,
	}, diags
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

	return newZone
}

func setTLSConfig(ctx context.Context, p12FileLocation string, p12Password string) error {
	tflog.Info(ctx, "Setting up TLS Configuration")
	tlsConfig := tls.Config{
		Renegotiation: tls.RenegotiateFreelyAsClient,
	}

	data, err := os.ReadFile(p12FileLocation)
	if err != nil {
		return fmt.Errorf("unable to read PKCS#12 file at [%s]: %w", p12FileLocation, err)
	}
	// We have a PKCS12 file to use, set it up for cert authentication
	blocks, err := pkcs12.ToPEM(data, p12Password)
	if err != nil {
		return fmt.Errorf("failed converting PKCS#12 archive file to PEM blocks: %w", err)
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	// Construct TLS certificate from PEM data
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return fmt.Errorf("failed reading PEM data to build X.509 certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(pemData)

	// Setup HTTPS client
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.RootCAs = caCertPool

	// Create own Transport to allow HTTP1.1 connections
	transport := &http.Transport{
		// Only one request is made with a client
		DisableKeepAlives: true,
		// This is to allow for http1.1 connections
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tlsConfig,
	}

	//Setting Default HTTP Transport
	http.DefaultTransport = transport

	return nil
}

func pingVenafi(ctx context.Context, config *vcert.Config) error {
	tflog.Info(ctx, fmt.Sprintf("Pinging Venafi Platform: %s", config.ConnectorType.String()))
	client, err := vcert.NewClient(config, false)
	if err != nil {
		return err
	}

	err = client.Ping()
	if err != nil {
		return err
	}

	tflog.Info(ctx, "Ping Successful")
	return nil
}

func getAccessTokenFromClientCertificate(ctx context.Context, config *vcert.Config) error {
	tflog.Info(ctx, "PFX Certificate provided for authentication: Trying to authenticate")
	client, err := vcert.NewClient(config, false)
	if err != nil {
		return err
	}

	resp, err := client.(*tpp.Connector).GetRefreshToken(config.Credentials)
	if err != nil {
		return err
	}

	config.Credentials.AccessToken = resp.Access_token

	tflog.Info(ctx, "Successfully authenticated")
	return nil
}
