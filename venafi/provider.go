package venafi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	messageVenafiPingFailed       = "Failed to ping Venafi endpoint: "
	messageVenafiPingSuccessful   = "Venafi ping successful"
	messageVenafiClientInitFailed = "Failed to initialize Venafi client"
	messageVenafiConfigFailed     = "Failed to build config for Venafi issuer: "
	messageUseDevMode             = "Using dev mode to issue certificate"
	messageUseVaas                = "Using VaaS to issue certificate"
	messageUseTLSPDC              = "Using Platform TLSPDC with url %s to issue certificate"

	utilityName     = "HashiCorp Terraform"
	defaultClientID = "hashicorp-terraform-by-venafi"

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

	// Attributes of the provider
	fURL         = "url"
	fZone        = "zone"
	fDevMode     = "dev_mode"
	fUsername    = "tpp_username"
	fPassword    = "tpp_password"
	fP12Cert     = "p12_cert"
	fP12Password = "p12_password"
	fAccessToken = "access_token"
	fApiKey      = "api_key"
	fTrustBundle = "trust_bundle"
	fClientID    = "client_id"
)

// Provider returns a terraform.ResourceProvider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			fURL: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiURL, nil),
				Description: "The Venafi Platform URL. Example: https://tpp.venafi.example/vedsdk",
			},
			fZone: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiZone, "Default"),
				Description: `DN of the Venafi TLSPDC policy folder or name of the Venafi as a Service application plus issuing template alias. 
Example for Platform: testPolicy\\vault
Example for Venafi as a Service: myApp\\Default`,
			},
			fUsername: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiUsername, nil),
				Description: "WebSDK user for Venafi TLSPDC. Example: admin",
				Deprecated:  ", please use access_token instead",
			},
			fPassword: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiPassword, nil),
				Description: "Password for WebSDK user. Example: password",
				Deprecated:  ", please use access_token instead",
				Sensitive:   true,
			},
			fAccessToken: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiAccessToken, nil),
				Description: "Access token for Venafi TLSPDC, user should use this for authentication",
				Sensitive:   true,
			},
			fP12Cert: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiP12Certificate, nil),
				Description: "base64-encoded PKCS#12 keystore containing a client certificate, private key, and chain certificates to authenticate to TLSPDC",
			},
			fP12Password: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiP12Password, nil),
				Description: "Password for the PKCS#12 keystore declared in p12_cert",
				Sensitive:   true,
			},
			fTrustBundle: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Use to specify a PEM-formatted file that contains certificates to be trust anchors for all communications with the Venafi Web Service.
Example:
  trust_bundle = "${file("chain.pem")}"`,
			},
			fApiKey: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiApiKey, nil),
				Description: `API key for Venafi as a Service. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
				Sensitive:   true,
			},
			fDevMode: {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiDevMode, nil),
				Description: `When set to true, the resulting certificate will be issued by an ephemeral, no trust CA rather than enrolling using Venafi as a Service or Trust Protection Platform. Useful for development and testing.`,
			},
			fClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(envVenafiClientID, defaultClientID),
				Description: "application that will be using the token",
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

	tflog.Info(ctx, "Configuring venafi provider")
	apiKey := d.Get(fApiKey).(string)
	url := d.Get(fURL).(string)
	tppUser := d.Get(fUsername).(string)
	tppPassword := d.Get(fPassword).(string)
	accessToken := d.Get(fAccessToken).(string)
	zone := d.Get(fZone).(string)
	zone = normalizeZone(zone)
	trustBundle := d.Get(fTrustBundle).(string)
	p12Certificate := d.Get(fP12Cert).(string)
	p12Password := d.Get(fP12Password).(string)
	clientID := d.Get(fClientID).(string)

	//Dev Mode
	devMode := d.Get(fDevMode).(bool)
	// TLSPDC auth methods
	userPassMethod := tppUser != "" && tppPassword != ""
	clientCertMethod := p12Certificate != "" && p12Password != ""
	accessTokenMethod := accessToken != ""
	// TLSPC auth methods
	apiKeyMethod := apiKey != ""

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	if !accessTokenMethod && !clientCertMethod && !userPassMethod && !apiKeyMethod && !devMode {
		tflog.Error(ctx, fmt.Sprintf("no authorization attributes defined in provider. "+
			"One of the following must be set: %s, %s/%s, %s/%s, or %s",
			fAccessToken, fP12Cert, fP12Password, fUsername, fPassword, fApiKey))
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiConfigFailed,
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
		insecure := trustBundle == ""
		tflog.Info(ctx, "no trust-bundle provided. setting up Connection as insecure")
		err := setTLSConfig(ctx, p12Certificate, p12Password, insecure)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  messageVenafiClientInitFailed,
				Detail:   messageVenafiConfigFailed + err.Error(),
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
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiConfigFailed,
		})
		return nil, diags
	}

	if trustBundle != "" {
		tflog.Info(ctx, "Using trusted certificate")
		tflog.Debug(ctx, fmt.Sprintf("Using trusted certificate: \n %s", trustBundle))
		cfg.ConnectionTrust = trustBundle
	}

	client, err := vcert.NewClient(&cfg)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  messageVenafiClientInitFailed,
			Detail:   messageVenafiConfigFailed + ": " + err.Error(),
		})
		return nil, diags
	}

	err = client.Ping()
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

func setTLSConfig(ctx context.Context, p12Certificate string, p12Password string, insecure bool) error {
	if insecure {
		tflog.Warn(ctx, "TLS Config set to skip verification of server's certificate chain and host name")
	}
	tlsConfig := tls.Config{
		Renegotiation:      tls.RenegotiateFreelyAsClient,
		InsecureSkipVerify: insecure,
	}

	// We have a PKCS12 file to use, set it up for cert authentication
	blocks, err := pkcs12.ToPEM([]byte(p12Certificate), p12Password)
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
