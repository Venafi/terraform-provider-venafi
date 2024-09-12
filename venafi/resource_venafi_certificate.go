package venafi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	importIdFailEmpty          = "the id for import method is empty"
	importIdFailExceededValues = "there are more attributes than expected in the import id being passed"
	importPickupIdFailEmpty    = "empty pickupID for VaaS or common_name for TPP during import method"
	importKeyPasswordFailEmpty = "empty key_password for import method" //#nosec
	importZoneFailEmpty        = "zone cannot be empty when importing certificate"
	terraformStateTainted      = "terraform state was modified by another party"
)

const (
	venafiCertificateAttrNickname      = "nickname"
	venafiCertificateAttrCertificateID = "certificate_id"
	venafiCertificateAttrRenew         = "renew_required"
)

func resourceVenafiCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVenafiCertificateCreate,
		ReadContext:   resourceVenafiCertificateRead,
		DeleteContext: resourceVenafiCertificateDelete,
		UpdateContext: resourceVenafiCertificateUpdate,
		Schema: map[string]*schema.Schema{
			"csr_origin": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Origin of the CSR. One of local or service. Local: The CSR will be generated locally and " +
					"sent over for certificate issuance. Service: The CSR will be generated and managed by the Venafi platform. Default is local",
				ForceNew: true,
				Default:  "local",
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Common name of the certificate",
				ForceNew:    true,
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Country of the certificate (C)",
				ForceNew:    true,
			},
			"state": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "State of the certificate (S)",
				ForceNew:    true,
			},
			"locality": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Locality/City of the certificate (L)",
				ForceNew:    true,
			},
			"organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Organization of the certificate (O)",
				ForceNew:    true,
			},
			"organizational_units": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of Organizational Units of the certificate (OU)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			venafiCertificateAttrNickname: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Use to specify a name for the new certificate object that will be created and placed in a policy. Only valid for TPP",
				ForceNew:    true,
			},
			"algorithm": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "RSA",
				Description: "Key encryption algorithm. RSA or ECDSA. RSA is default",
			},
			"rsa_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of bits to use when generating an RSA key",
				ForceNew:    true,
				Default:     2048,
			},
			"ecdsa_curve": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ECDSA curve to use when generating a key",
				ForceNew:    true,
				Default:     "P521",
			},
			"san_dns": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of DNS names to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"san_email": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of email addresses to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"san_ip": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of IP addresses to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"san_uri": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of Uniform Resource Identifiers (URIs) to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key_password": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Password for the private key",
				Sensitive:   true,
			},
			"expiration_window": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of hours before the certificates expiry when a new certificate will be generated",
				Default:     expirationWindowDefault,
			},
			"private_key_pem": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"chain": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"certificate": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"csr_pem": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pkcs12": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"certificate_dn": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Description: "Data map in the form key=\"value1|value2|...|valueN\", to be added to the certificate",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"valid_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "The desired validity time for the certificate, in days",
			},
			"issuer_hint": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Indicate the target issuer to enable valid days with Venafi Platform. Supported values are DigiCert, Entrust, and Microsoft",
			},
			venafiCertificateAttrCertificateID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the issued certificate",
			},
			venafiCertificateAttrRenew: {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "Indicates the certificate should be reissued. This means the resource will destroyed and recreated",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceVenafiCertificateImport,
		},
	}
}

func resourceVenafiCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	tflog.Info(ctx, "Creating certificate\n")

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	cl, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Info(ctx, messageVenafiPingSuccessful)

	err = enrollVenafiCertificate(ctx, d, cl)
	if err != nil {
		return diag.FromErr(err)
	}

	origin := d.Get("csr_origin").(string)
	_, passOk := d.GetOk("key_password")

	//Add warning message when no password for private key was set and CSR origin is service.
	if origin == csrService && !passOk {
		detailMsg := "No key password provided for service generated CSR. Certificate contents (certificate, chain, private key) not stored in terraform state"
		tflog.Info(ctx, detailMsg)
	}

	return diags
}

func resourceVenafiCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	//casting meta interface to the expected *ProviderConfig
	provConf, ok := meta.(*ProviderConfig)
	if !ok {
		castError := errors.New(messageVenafiProviderConfigCastingFailed)
		tflog.Error(ctx, castError.Error())
		return diag.FromErr(castError)
	}
	vCertCfg := provConf.VCertConfig

	cl, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	certID := d.Id()
	parameters := strings.Split(certID, ",")

	var keyPassword string
	var keyPasswordFromImport string
	var pickupID string

	// When retrieving the certID we have to watch for two cases: when certificate is imported and when is not
	// For both cases we get the pickupID from the first parameter and the key password from state
	pickupID = parameters[0]

	keyPasswordUntyped, ok := d.GetOk("key_password")
	if ok {
		keyPassword = keyPasswordUntyped.(string)
	}

	// But we need to make extra verifications if state was tainted by a third party.
	// We ignore the case when parameters length is equal to 1, since that's standard accepted case when certificate is not imported.
	if len(parameters) < 1 {
		return buildStandardDiagError(fmt.Sprintf("%s: certID was not found from terraform state", terraformStateTainted))
	} else if len(parameters) == 2 {
		// since the key password is also within the certID, we want to verify if it differs from the one defined at state
		keyPasswordFromImport = parameters[1]
		if keyPassword != "" {
			if keyPassword != keyPasswordFromImport {
				return buildStandardDiagError(fmt.Sprintf("%s: key passwords mismatch! the key_password defined in the id,, differs from the attribute key_password defined at terraform state", terraformStateTainted))
			}
		}
	} else if len(parameters) > 2 {
		return buildStandardDiagError(fmt.Sprintf("%s: many values were found defined at certID from terraform state", terraformStateTainted))
	}

	zone := vCertCfg.Zone
	if cl.GetType() == endpoint.ConnectorTypeTPP {
		zone = buildAbsoluteZoneTPP(zone)
		ok := strings.Contains(pickupID, zone)
		if !ok {
			pickupID = fmt.Sprintf("%s\\%s", zone, pickupID)
		}

	}

	origin := d.Get("csr_origin").(string)
	pickupReq := fillRetrieveRequest(pickupID, keyPassword, origin)

	data, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		// if certificate does not exist, we get the following error message:
		var notFoundMsg string
		// For VaaS
		if cl.GetType() == endpoint.ConnectorTypeCloud {
			notFoundMsg = "Not Found"
		} else {
			// For TPP
			// "Certificate \\VED\\Policy\\test\\cert_id does not exist."
			notFoundMsg = "does not exist"
		}
		strErr := (err).Error()

		ok := strings.Contains(strErr, notFoundMsg)
		if ok {
			tflog.Warn(ctx, fmt.Sprintf("certificate (%s) not found, removing from state", d.Id()))
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	err = d.Set(venafiCertificateAttrCertificateID, pickupReq.CertID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting certificate id attribute: %w", err))
	}

	d.SetId(pickupReq.PickupID)

	stateCertUntyped, ok := d.GetOk("certificate")
	certPEM := data.Certificate
	if ok {
		// Check certificate
		stateCertPEM := stateCertUntyped.(string)
		if certPEM != stateCertPEM {
			diag.FromErr(fmt.Errorf("certificate (%s) from remote differs from the one defined at state", d.Id()))
		}

		//Checking Private Key
		if privateKeyUntyped, ok := d.GetOk("private_key_pem"); ok {
			privateKey := privateKeyUntyped.(string)
			err = verifyCertKeyPair(certPEM, privateKey, keyPassword)
			if err != nil {
				diag.FromErr(err)
			}
		}
	}

	// Check if certificate needs to be renewed
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error parsing cert: %s", err))
	}

	renewRequired := checkForRenew(*cert, d.Get("expiration_window").(int))
	if renewRequired {
		detailMsg := fmt.Sprintf("Certificate %s expires %s and should be renewed because it`s less than %d hours at this date", d.Id(), cert.NotAfter, d.Get("expiration_window").(int))
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Certificate About to Expire",
			Detail:   detailMsg,
		})
	}
	err = d.Set(venafiCertificateAttrRenew, renewRequired)
	if err != nil {
		return diag.FromErr(err)
	}
	return diags
}

func resourceVenafiCertificateUpdate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	if d.HasChange("expiration_window") {
		// Getting expiration_window from state
		expirationWindow := d.Get("expiration_window").(int)
		// Getting certificate
		certUntyped, ok := d.GetOk("certificate")
		if !ok {
			return diag.FromErr(fmt.Errorf("cert is nil"))
		}
		certPEM := certUntyped.(string)
		// validating expiration_window
		_, _, err := validExpirationWindowCert(certPEM, expirationWindow)
		if err != nil {
			return diag.FromErr(err)
		}
		err = d.Set("expiration_window", expirationWindow)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	if d.HasChange(venafiCertificateAttrRenew) {
		renew := d.Get(venafiCertificateAttrRenew).(bool)
		err := d.Set(venafiCertificateAttrRenew, renew)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceVenafiCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) (diags diag.Diagnostics) {
	//casting meta interface to the expected *ProviderConfig
	provConf, ok := meta.(*ProviderConfig)
	if !ok {
		castError := errors.New(messageVenafiProviderConfigCastingFailed)
		tflog.Error(ctx, castError.Error())
		return diag.FromErr(castError)
	}
	vCertCfg := provConf.VCertConfig

	//VCert connector fake has not implemented the RetireCertificate functionality
	if provConf.SkipRetirement || vCertCfg.ConnectorType == endpoint.ConnectorTypeFake {
		// removing it from state
		d.SetId("")
		return nil
	}

	cl, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	certID := d.Id()
	parameters := strings.Split(certID, ",")

	// When retrieving the certID we have to watch for two cases: when certificate is imported and when is not
	// For both cases we get the pickupID from the first parameter and the key password from state
	pickupID := parameters[0]

	// But we need to make extra verifications if state was tainted by a third party.
	// We ignore the case when parameters length is equal to 1, since that's standard accepted case when certificate is not imported.
	if len(parameters) < 1 {
		return buildStandardDiagError(fmt.Sprintf("%s: certificate ID not found in terraform state", terraformStateTainted))
	} else if len(parameters) > 2 {
		return buildStandardDiagError(fmt.Sprintf("%s: certificate ID not found in terraform state. Too many values", terraformStateTainted))
	}

	zone := vCertCfg.Zone
	if cl.GetType() == endpoint.ConnectorTypeTPP {
		zone = buildAbsoluteZoneTPP(zone)
		ok := strings.Contains(pickupID, zone)
		if !ok {
			pickupID = fmt.Sprintf("%s\\%s", zone, pickupID)
		}
	}

	if err = cl.RetireCertificate(&certificate.RetireRequest{CertificateDN: pickupID}); err != nil {
		tflog.Error(ctx, "failed to retire the certificate "+err.Error())
		return diag.FromErr(err)
	}

	// removing it from state
	d.SetId("")

	return nil
}

func verifyCertKeyPair(certPEM string, privateKeyPEM string, keyPassword string) error {
	var pk8PEMBytes []byte
	var pk1PEMBytes []byte

	pk8PEM, err := util.DecryptPkcs8PrivateKey(privateKeyPEM, keyPassword)
	if err != nil {
		pk1PEMBytes, err = getPrivateKey([]byte(privateKeyPEM), keyPassword)
		if err != nil {
			return err
		}
	}

	pk8PEMBytes = []byte(pk8PEM)
	_, err = tls.X509KeyPair([]byte(certPEM), pk8PEMBytes)
	if err != nil {
		if len(pk1PEMBytes) != 0 {
			_, err = tls.X509KeyPair([]byte(certPEM), pk1PEMBytes)
			if err != nil {
				return fmt.Errorf("error comparing certificate and key: %s", err)
			}
		}
		return fmt.Errorf("error comparing certificate and key: %s", err)
	}
	return nil
}

// validExpirationWindowCert checks if the expiration_window the expiration_window is greater than the validity_period
// receives the certificate in PEM format as a string type and expiration window in time.Duration type (converted to hours)
// returns a boolean value of true if expiration_window is greater and logs it in a message, else returns false and doesn't log a message, and any error encountered
func validExpirationWindowCert(certPem string, expirationWindow int) (boolean bool, duration *time.Duration, err error) {
	cert, err := parseCertificate(certPem)
	if err != nil {
		return false, nil, err
	}
	certDuration := getCertDuration(cert)
	expirationWindowDuration := time.Duration(expirationWindow) * time.Hour
	ok := validExpirationWindow(certDuration, expirationWindowDuration)
	return ok, &certDuration, nil
}

func getCertDuration(cert *x509.Certificate) (duration time.Duration) {
	currentDuration := cert.NotAfter.Sub(cert.NotBefore)
	return currentDuration
}

// validExpirationWindow checks if the expiration_window is greater than the validity_period
// receives the certificate duration in time.Duration type (converted to hours) type and expiration window in time.Duration type (converted to hours)
// returns a boolean value of true if expiration_window is greater and logs it in a message, else returns false and doesn't log a message
func validExpirationWindow(certDuration time.Duration, expirationWindowHours time.Duration) (boolean bool) {
	if certDuration < expirationWindowHours {
		log.Printf("[INFO] certificate validity duration %s is less than configured expiration window %s", certDuration, expirationWindowHours)
		return true
	}
	return false
}

func checkForRenew(cert x509.Certificate, expirationWindow int) (renewRequired bool) {
	renewWindow := time.Duration(expirationWindow) * time.Hour
	certDuration := getCertDuration(&cert)
	validExpirationWindow(certDuration, renewWindow)
	renewRequired = time.Now().Add(renewWindow).After(cert.NotAfter)
	return renewRequired
}

func enrollVenafiCertificate(ctx context.Context, d *schema.ResourceData, cl endpoint.Connector) error {

	req := &certificate.Request{
		CsrOrigin:    certificate.LocalGeneratedCSR,
		CustomFields: []certificate.CustomField{{Type: certificate.CustomFieldOrigin, Value: utilityName}},
	}

	origin := d.Get("csr_origin").(string)
	if origin == csrService {
		req.CsrOrigin = certificate.ServiceGeneratedCSR
	}

	//setting DN values Org, Organization Units, Country, State, Locality(City)
	country := d.Get("country").(string)
	if country != "" {
		req.Subject.Country = []string{country}
	}
	state := d.Get("state").(string)
	if state != "" {
		req.Subject.Province = []string{state}
	}
	locality := d.Get("locality").(string)
	if locality != "" {
		req.Subject.Locality = []string{locality}
	}
	org := d.Get("organization").(string)
	if org != "" {
		req.Subject.Organization = []string{org}
	}
	orgUnits := d.Get("organizational_units").([]interface{})
	for _, orgUnit := range orgUnits {
		orgUnitStr := orgUnit.(string)
		req.Subject.OrganizationalUnit = append(req.Subject.OrganizationalUnit, orgUnitStr)
	}

	//Configuring keys
	keyType := d.Get("algorithm").(string)

	var keyPassword string
	if pass, ok := d.GetOk("key_password"); ok {
		keyPassword = pass.(string)
		req.KeyPassword = keyPassword
	}

	if keyType == "RSA" || len(keyType) == 0 {
		req.KeyLength = d.Get("rsa_bits").(int)
		req.KeyType = certificate.KeyTypeRSA
	} else if keyType == "ECDSA" {
		keyCurve := d.Get("ecdsa_curve").(string)
		req.KeyType = certificate.KeyTypeECDSA
		err := req.KeyCurve.Set(keyCurve)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("can't determine key algorithm %s", keyType)
	}

	//Setting up Subject
	commonName := d.Get("common_name").(string)
	//Adding alt names if exists
	dnsNum := d.Get("san_dns.#").(int)
	if dnsNum > 0 {
		for i := 0; i < dnsNum; i++ {
			key := fmt.Sprintf("san_dns.%d", i)
			val := d.Get(key).(string)
			tflog.Info(ctx, fmt.Sprintf("Adding SAN %s.", val))
			req.DNSNames = append(req.DNSNames, val)
		}
	}

	if len(commonName) == 0 && len(req.DNSNames) == 0 {
		return fmt.Errorf("no domains specified on certificate")
	}
	if len(commonName) == 0 && len(req.DNSNames) > 0 {
		commonName = req.DNSNames[0]
	}
	if !sliceContains(req.DNSNames, commonName) {
		tflog.Info(ctx, fmt.Sprintf("Adding CN %s to SAN %s because it wasn't included.", commonName, req.DNSNames))
		req.DNSNames = append(req.DNSNames, commonName)
	}
	if cl.GetType() == endpoint.ConnectorTypeTPP {
		friendlyName := d.Get(venafiCertificateAttrNickname).(string)
		if friendlyName != "" {
			req.FriendlyName = friendlyName
		}
	}

	//Obtain a certificate from the Venafi server
	tflog.Info(ctx, fmt.Sprintf("Using CN %s and SAN %s", commonName, req.DNSNames))
	req.Subject.CommonName = commonName

	emailNum := d.Get("san_email.#").(int)
	if emailNum > 0 {
		for i := 0; i < emailNum; i++ {
			key := fmt.Sprintf("san_email.%d", i)
			val := d.Get(key).(string)
			req.EmailAddresses = append(req.EmailAddresses, val)
		}
	}
	ipNum := d.Get("san_ip.#").(int)
	if ipNum > 0 {
		ipList := make([]string, 0, ipNum)
		for i := 0; i < ipNum; i++ {
			key := fmt.Sprintf("san_ip.%d", i)
			val := d.Get(key).(string)
			ipList = append(ipList, val)
		}
		for i := 0; i < len(ipList); i += 1 {
			ip := net.ParseIP(ipList[i])
			if ip == nil {
				return fmt.Errorf("invalid IP address %#v", ipList[i])
			}
			req.IPAddresses = append(req.IPAddresses, ip)
		}
	}
	sanUriLen := d.Get("san_uri.#").(int)
	if sanUriLen > 0 {
		uriList := make([]string, 0, sanUriLen)
		for i := 0; i < sanUriLen; i++ {
			key := fmt.Sprintf("san_uri.%d", i)
			val := d.Get(key).(string)
			uriList = append(uriList, val)
		}
		for i := 0; i < len(uriList); i += 1 {
			uri, err := url.Parse(uriList[i])
			if err != nil {
				return fmt.Errorf("invalid URI: %s", err.Error())
			}
			req.URIs = append(req.URIs, uri)
		}
	}

	//Appending common name to the DNS names if it is not there
	if !sliceContains(req.DNSNames, commonName) {
		tflog.Info(ctx, fmt.Sprintf("Adding CN %s to SAN because it wasn't included.", commonName))
		req.DNSNames = append(req.DNSNames, commonName)
	}

	tflog.Info(ctx, fmt.Sprintf("Requested SAN: %s", req.DNSNames))

	if origin != csrService {
		var err error
		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return fmt.Errorf("unable to generate certificate request, key type %s is not supported", req.KeyType.String())
		}
		if err != nil {
			return fmt.Errorf("error generating key: %s", err)
		}
	}

	//Adding custom fields to request
	customFields, ok := d.GetOk("custom_fields")
	if ok {
		customFields := customFields.(map[string]interface{})
		for key, values := range customFields {
			values, ok = values.(string)
			if !ok {
				return fmt.Errorf("error in custom field [%s]. Expected a comma separated string, got: %s", key, values)
			}
			values = strings.TrimSpace(values.(string))
			list := strings.Split(values.(string), "|")
			for _, value := range list {
				value = strings.TrimSpace(value)
				req.CustomFields = append(req.CustomFields, certificate.CustomField{Name: key, Value: value})
			}
		}
	}

	ttl, ok := d.GetOk("valid_days")
	if ok {
		validity := ttl.(int)
		validity = validity * 24
		req.ValidityHours = validity //nolint:staticcheck
		issuerHint := d.Get("issuer_hint").(string)
		req.IssuerHint = getIssuerHint(issuerHint)
	}

	tflog.Info(ctx, "Making certificate request")
	err := cl.GenerateRequest(nil, req)
	if err != nil {
		return err
	}

	requestID, err := cl.RequestCertificate(req)
	if err != nil {
		return err
	}

	pickupPass := ""
	if origin == csrService {
		if pass, ok := d.GetOk("key_password"); ok {
			pickupPass = pass.(string)
		}
	}

	pickupReq := fillRetrieveRequest(requestID, pickupPass, origin)

	err = d.Set("certificate_dn", requestID)
	if err != nil {
		return err
	}

	pcc, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return err
	}

	err = d.Set(venafiCertificateAttrCertificateID, pickupReq.CertID)
	if err != nil {
		return fmt.Errorf("error setting certificate id attribute: %w", err)
	}

	d.SetId(req.PickupID)

	if origin == csrService && keyPassword == "" {
		// Nothing else to do here. Send warning message, certificate contents not stored in state
		return nil
	}

	if origin != csrService {
		if pass, ok := d.GetOk("key_password"); ok {
			err = pcc.AddPrivateKey(req.PrivateKey, []byte(pass.(string)))
		} else {
			err = pcc.AddPrivateKey(req.PrivateKey, []byte(""))
		}
		if err != nil {
			return err
		}
	}

	tflog.Info(ctx, "Creating certificate resource: Verifying certificate key-pair")
	err = verifyCertKeyPair(pcc.Certificate, pcc.PrivateKey, keyPassword)
	if err != nil {
		return fmt.Errorf("Could not add certificate resource to state. Certificate and private key mismatch. Err: %s", err.Error())
	}

	if err = d.Set("certificate", pcc.Certificate); err != nil {
		return fmt.Errorf("error setting certificate: %s", err)
	}
	tflog.Info(ctx, fmt.Sprintf("Certificate set to %s", pcc.Certificate))

	if err = d.Set("chain", strings.Join(pcc.Chain, "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
	}
	tflog.Info(ctx, fmt.Sprintf("Certificate chain set to %s", pcc.Chain))

	tflog.Info(ctx, "Setting up private key")

	privKey, err := util.DecryptPkcs8PrivateKey(pcc.PrivateKey, keyPassword)
	if err != nil {
		return err
	}

	certPkcs12, err := AsPKCS12(pcc.Certificate, privKey, pcc.Chain, keyPassword)

	if err != nil {
		return err
	}

	s := base64.StdEncoding.EncodeToString(certPkcs12)
	if err = d.Set("pkcs12", s); err != nil {
		return fmt.Errorf("error setting pkcs12: %s", err)
	}

	if err = d.Set("private_key_pem", pcc.PrivateKey); err != nil {
		return fmt.Errorf("error setting private key: %s", err)
	}

	return nil
}

func AsPKCS12(certificate string, privateKey string, chain []string, keyPassword string) ([]byte, error) {

	if len(certificate) == 0 || len(privateKey) == 0 {
		return nil, fmt.Errorf("at least certificate and private key are required")
	}
	p, _ := pem.Decode([]byte(certificate))
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate parse error(1)")
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate parse error(2)")
	}

	// chain?
	var chainList = []*x509.Certificate{}
	for _, chainCert := range chain {
		crt, _ := pem.Decode([]byte(chainCert))
		cert, err := x509.ParseCertificate(crt.Bytes)
		if err != nil {
			return nil, fmt.Errorf("chain certificate parse error")
		}
		chainList = append(chainList, cert)
	}

	// key?
	p, _ = pem.Decode([]byte(privateKey))
	if p == nil {
		return nil, fmt.Errorf("missing private key PEM")
	}
	var privDER []byte
	if util.X509IsEncryptedPEMBlock(p) {
		privDER, err = util.X509DecryptPEMBlock(p, []byte(keyPassword))
		if err != nil {
			return nil, fmt.Errorf("private key PEM decryption error: %s", err)
		}
	} else {
		privDER = p.Bytes
	}
	var privKey interface{}
	switch p.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	default:
		return nil, fmt.Errorf("unexpected private key PEM type: %s", p.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("private key error(3): %s", err)
	}

	bytes, err := pkcs12.LegacyRC2.Encode(privKey, cert, chainList, keyPassword)
	if err != nil {
		return nil, fmt.Errorf("encode error: %s", err)
	}

	return bytes, nil
}

func resourceVenafiCertificateImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	logFields := map[string]interface{}{
		"id": id,
	}
	tflog.Info(ctx, "Importing Venafi certificate", logFields)

	if id == "" {
		return nil, errors.New(importIdFailEmpty)
	}

	parameters := strings.Split(id, ",")

	var pickupID string
	var keyPassword string

	if len(parameters) > 2 {
		return nil, errors.New(importIdFailExceededValues)
	}

	if len(parameters) >= 1 {
		pickupID = parameters[0]
		if pickupID == "" {
			return nil, errors.New(importPickupIdFailEmpty)
		}
	}
	if len(parameters) == 2 {
		keyPassword = parameters[1]
		if keyPassword == "" {
			return nil, errors.New(importKeyPasswordFailEmpty)
		}
	}

	//casting meta interface to the expected *ProviderConfig
	provConf, ok := meta.(*ProviderConfig)
	if !ok {
		castError := errors.New(messageVenafiProviderConfigCastingFailed)
		return nil, castError
	}
	vCertCfg := provConf.VCertConfig
	zone := vCertCfg.Zone
	if zone == "" {
		return nil, errors.New(importZoneFailEmpty)
	}

	cl, err := getConnection(ctx, meta)
	if err != nil {
		return nil, err
	}

	if cl.GetType() == endpoint.ConnectorTypeTPP {
		zone = buildAbsoluteZoneTPP(zone)
		pickupID = fmt.Sprintf("%s\\%s", zone, pickupID)
	}

	pickupReq := fillRetrieveRequest(pickupID, keyPassword, csrService)

	data, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		strErr := (err).Error()
		if strErr == "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 400 Failed to lookup private key, error: Failed to lookup private key vault id" {
			return nil, fmt.Errorf("%s - private key was service generated? Import method does not support importing of local generated private keys", err)
		}
		return nil, err
	}

	var certMetadata *certificate.CertificateMetaData
	if cl.GetType() == endpoint.ConnectorTypeTPP {
		certMetadata, err = cl.RetrieveCertificateMetaData(pickupID)
		if err != nil {
			return nil, err
		}
	}

	if pickupReq.CertID != "" {
		err = d.Set(venafiCertificateAttrCertificateID, pickupReq.CertID)
		if err != nil {
			return nil, err
		}
	}

	err = fillSchemaPropertiesImport(d, data, certMetadata, pickupID, keyPassword, cl.GetType())
	if err != nil {
		return nil, err
	}
	if keyPassword == "" {
		detailMsg := "No key password provided for certificate import. Certificate contents (certificate, chain, private key) not stored in terraform state"
		tflog.Info(ctx, detailMsg)
	}

	return []*schema.ResourceData{d}, nil
}

func fillRetrieveRequest(id string, password string, origin string) *certificate.Request {
	pickupReq := &certificate.Request{}
	pickupReq.Timeout = 180 * time.Second
	pickupReq.PickupID = id
	pickupReq.KeyPassword = password

	if origin == csrService && password != "" {
		pickupReq.FetchPrivateKey = true
	}
	return pickupReq
}

func fillSchemaPropertiesImport(d *schema.ResourceData, data *certificate.PEMCollection, certMetadata *certificate.CertificateMetaData,
	id string, keyPassword string, connectorType endpoint.ConnectorType) error {
	err := d.Set("csr_origin", csrService)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(data.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing cert: %s", err)
	}

	err = d.Set("common_name", cert.Subject.CommonName)
	if err != nil {
		return err
	}

	err = d.Set("san_email", cert.EmailAddresses)
	if err != nil {
		return err
	}

	err = d.Set("san_dns", cert.DNSNames)
	if err != nil {
		return err
	}

	err = d.Set("certificate_dn", id)
	if err != nil {
		return err
	}

	ipAddresses := IPArrayToStringArray(cert.IPAddresses)
	err = d.Set("san_ip", ipAddresses)
	if err != nil {
		return err
	}

	URIs := UriArrayToStringArray(cert.URIs)
	err = d.Set("san_uri", URIs)
	if err != nil {
		return err
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	certValidDays := int64(math.Floor(duration.Hours() / 24))
	err = d.Set("valid_days", certValidDays)
	if err != nil {
		return err
	}

	// Only store certificate information if key_password is present
	if keyPassword != "" {
		err = d.Set("certificate", data.Certificate)
		if err != nil {
			return err
		}

		err = d.Set("private_key_pem", data.PrivateKey)
		if err != nil {
			return err
		}

		err = d.Set("chain", strings.Join(data.Chain, ""))
		if err != nil {
			return fmt.Errorf("error setting chain: %w", err)
		}

		err = d.Set("key_password", keyPassword)
		if err != nil {
			return err
		}

		privDER, _ := pem.Decode([]byte(data.PrivateKey))
		key, _, parSeErr := pkcs8.ParsePrivateKey(privDER.Bytes, []byte(keyPassword))
		if parSeErr != nil {
			return parSeErr
		}

		var pemType string
		// We are adding the default values for other algorithms,
		// since Terraform expects them as they are defined as defaults in the schema
		switch keyValue := key.(type) {
		case *rsa.PrivateKey:
			err = d.Set("algorithm", "RSA")
			if err != nil {
				return err
			}
			err = d.Set("rsa_bits", keyValue.N.BitLen())
			if err != nil {
				return err
			}
			// Setting default value for other algorithm as mentioned above
			err = d.Set("ecdsa_curve", "P521")
			if err != nil {
				return err
			}
			pemType = "RSA PRIVATE KEY"
		case *ecdsa.PrivateKey:
			if connectorType == endpoint.ConnectorTypeCloud {
				return fmt.Errorf("ecdsa private key import operation currently is not supported for VaaS")
			}
			keySize := strconv.Itoa(keyValue.Curve.Params().BitSize)
			err = d.Set("ecdsa_curve", fmt.Sprintf("P%s", keySize))
			if err != nil {
				return err
			}
			err = d.Set("rsa_bits", 2048)
			if err != nil {
				return err
			}
			// Setting default value for other algorithm as mentioned above
			err = d.Set("algorithm", "ECDSA")
			if err != nil {
				return err
			}
			pemType = "EC PRIVATE KEY"
		default:
			return fmt.Errorf("failed to determine private key type")
		}

		privateKeyBytes, pkErr := pkcs8.MarshalPrivateKey(key, nil, nil)
		if pkErr != nil {
			return pkErr
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: privateKeyBytes})
		certPkcs12, p12Err := AsPKCS12(data.Certificate, string(pemBytes), data.Chain, keyPassword)
		if p12Err != nil {
			return p12Err
		}

		certPkcs12string := base64.StdEncoding.EncodeToString(certPkcs12)
		err = d.Set("pkcs12", certPkcs12string)
		if err != nil {
			return err
		}
	}

	if connectorType == endpoint.ConnectorTypeTPP {
		// only TPP handle the concept of object name so only then we set it
		// we are expecting "id" have something like \\VED\\Policy\\MyPolicy\\my-object-name
		certificateDNsplit := strings.Split(id, "\\")
		nickname := certificateDNsplit[len(certificateDNsplit)-1]
		err = d.Set(venafiCertificateAttrNickname, nickname)
		if err != nil {
			return err
		}

		customFields := certMetadata.CustomFields
		newCustomFields := make(map[string]interface{})
		for _, customField := range customFields {
			if customField.Type == "List" {
				newCustomFields[customField.Name] = strings.Join(customField.Value, "|")
			} else if customField.Type == "DateTime" {
				dateFormatRFC3339 := customField.Value[0]
				currentFormat, err := time.Parse(time.RFC3339, dateFormatRFC3339)
				if err != nil {
					return err
				}
				// Our date field at TPP currently only supports until minutes: yyyy-mm-dd HH:mm
				newCustomFields[customField.Name] = currentFormat.Format("2006-01-02 15:04")

			} else {
				newCustomFields[customField.Name] = customField.Value[0]
			}
		}
		err = d.Set("custom_fields", newCustomFields)
		if err != nil {
			return err
		}
	}

	err = d.Set("expiration_window", expirationWindowDefault)
	if err != nil {
		return err
	}
	return nil
}

func buildAbsoluteZoneTPP(zone string) string {
	//Add leading forward slash e.g. Policy1\\Policy2 -> \\Policy1\\Policy2
	if !strings.HasPrefix(zone, util.PathSeparator) {
		zone = util.PathSeparator + zone
	}

	//Add leading ved-policy prefix e.g. \\Policy1\\Policy2 -> \\VED\\Policy\\Policy1\\Policy2
	if !strings.HasPrefix(zone, policy.RootPath) {
		zone = policy.RootPath + zone
	}

	return zone
}

func IPArrayToStringArray(ipArray []net.IP) []string {
	s := make([]string, 0)
	for _, ip := range ipArray {
		s = append(s, ip.String())
	}
	return s
}

func UriArrayToStringArray(uriArray []*url.URL) []string {
	s := make([]string, 0)
	for _, uri := range uriArray {
		s = append(s, uri.String())
	}
	return s
}

func parseCertificate(certPem string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certPem))
	var parsedCert *x509.Certificate
	parsedCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedCert, nil
}
