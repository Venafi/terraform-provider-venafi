package venafi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/youmark/pkcs8"
	"math"
	"net"
	"software.sslmate.com/src/go-pkcs12"
	"strconv"
	"time"

	"crypto/x509"
	"encoding/pem"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"log"
	"strings"
)

func resourceVenafiCertificate() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiCertificateCreate,
		Read:   resourceVenafiCertificateRead,
		Delete: resourceVenafiCertificateDelete,
		Exists: resourceVenafiCertificateExists,

		Schema: map[string]*schema.Schema{
			"csr_origin": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "csr origin",
				ForceNew:    true,
				Default:     "local",
			},
			"common_name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "Common name of certificate",
				ForceNew:    true,
			},
			"algorithm": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "RSA",
				Description: "Key encryption algorithm. RSA or ECDSA. RSA is default.",
			},
			"rsa_bits": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of bits to use when generating an RSA key",
				ForceNew:    true,
				Default:     2048,
			},

			"ecdsa_curve": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ECDSA curve to use when generating a key",
				ForceNew:    true,
				Default:     "P521",
			},

			"san_dns": &schema.Schema{
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of DNS names to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"san_email": &schema.Schema{
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of email addresses to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"san_ip": &schema.Schema{
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of IP addresses to use as subjects of the certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key_password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Private key password.",
				Sensitive:   true,
			},
			"expiration_window": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of hours before the certificates expiry when a new certificate will be generated",
				ForceNew:    true,
			},
			"private_key_pem": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"chain": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"certificate": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"csr_pem": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pkcs12": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"certificate_dn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"custom_fields": &schema.Schema{
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Description: "Data map in the form key=\"value1|value2|...|valueN\", to be added to the certificate",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"valid_days": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "The desired certificate requested time of validity",
			},
			"issuer_hint": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Indicate the target issuer to enable valid days with Venafi Platform; DigiCert, Entrust, and Microsoft are supported values.",
			},
		},
		Importer: &schema.ResourceImporter{
			State: resourceVenafiCertificateImport,
		},
	}
}

func resourceVenafiCertificateCreate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("Creating certificate\n")
	cfg := meta.(*vcert.Config)
	cl, err := vcert.NewClient(cfg)
	if err != nil {
		log.Printf(messageVenafiClientInitFailed + err.Error())
		return err
	}
	err = cl.Ping()
	if err != nil {
		log.Printf(messageVenafiPingFailed + err.Error())
		return err
	}
	log.Println(messageVenafiPingSuccessful)

	err = enrollVenafiCertificate(d, cl)
	if err != nil {
		return err
	}
	return nil
}

func resourceVenafiCertificateRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceVenafiCertificateExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	certUntyped, ok := d.GetOk("certificate")
	if !ok {
		return false, nil
	}
	certPEM := certUntyped.(string)
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("error parsing cert: %s", err)
	}
	//Checking Private Key
	var pk []byte
	if pkUntyped, ok := d.GetOk("private_key_pem"); ok {
		origin := d.Get("csr_origin")
		keyType := d.Get("algorithm")
		if origin != csrService && keyType == "ECDSA" {
			pk, err = getPrivateKey([]byte(pkUntyped.(string)), d.Get("key_password").(string))
			if err != nil {
				return false, fmt.Errorf("error getting key: %s", err)
			}
		} else {
			keyStr, err := util.DecryptPkcs8PrivateKey(pkUntyped.(string), d.Get("key_password").(string))
			if err != nil {
				return false, err
			}
			pk = []byte(keyStr)
		}

	} else {
		return false, fmt.Errorf("error getting key")
	}
	_, err = tls.X509KeyPair([]byte(certPEM), pk)
	if err != nil {
		return false, fmt.Errorf("error comparing certificate and key: %s", err)
	}

	//TODO: maybe this check should be up on CSR creation
	renewRequired, err := checkForRenew(*cert, d.Get("expiration_window").(int))
	if err != nil {
		return false, err
	}
	if renewRequired {
		//TODO: get request id from resource id
		log.Printf("Certificate expires %s and should be renewed becouse it`s less than %d hours at this date. Requesting", cert.NotAfter, d.Get("expiration_window").(int))
		return false, nil
	}

	return true, nil
}

func checkForRenew(cert x509.Certificate, expirationWindow int) (renewRequired bool, err error) {
	renewWindow := time.Duration(expirationWindow) * time.Hour
	if cert.NotAfter.Sub(cert.NotBefore) < renewWindow {
		err = fmt.Errorf("certificate validity duration %s is less than configured expiration window %s", cert.NotAfter.Sub(cert.NotBefore), renewWindow)
		return
	}
	renewRequired = time.Now().Add(renewWindow).After(cert.NotAfter)
	return
}

func resourceVenafiCertificateDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func enrollVenafiCertificate(d *schema.ResourceData, cl endpoint.Connector) error {

	req := &certificate.Request{
		CsrOrigin:    certificate.LocalGeneratedCSR,
		CustomFields: []certificate.CustomField{{Type: certificate.CustomFieldOrigin, Value: utilityName}},
	}

	origin := d.Get("csr_origin").(string)
	if origin == csrService {
		req.CsrOrigin = certificate.ServiceGeneratedCSR
		if pass, ok := d.GetOk("key_password"); ok {
			resolvedPass := pass.(string)
			if strings.TrimSpace(resolvedPass) == "" {
				return fmt.Errorf("key_password is empty")
			}
		} else {
			return fmt.Errorf("key_password is required")
		}
	}

	//Configuring keys
	var (
		err         error
		keyPassword string
	)

	keyType := d.Get("algorithm").(string)

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
		err = req.KeyCurve.Set(keyCurve)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("can't determine key algorithm %s", keyType)
	}

	//Setting up Subject
	commonName := d.Get("common_name").(string)
	//Adding alt names if exists
	dnsnum := d.Get("san_dns.#").(int)
	if dnsnum > 0 {
		for i := 0; i < dnsnum; i++ {
			key := fmt.Sprintf("san_dns.%d", i)
			val := d.Get(key).(string)
			log.Printf("Adding SAN %s.", val)
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
		log.Printf("Adding CN %s to SAN %s because it wasn't included.", commonName, req.DNSNames)
		req.DNSNames = append(req.DNSNames, commonName)
	}

	//Obtain a certificate from the Venafi server
	log.Printf("Using CN %s and SAN %s", commonName, req.DNSNames)
	req.Subject.CommonName = commonName

	emailnum := d.Get("san_email.#").(int)
	if emailnum > 0 {
		for i := 0; i < emailnum; i++ {
			key := fmt.Sprintf("san_email.%d", i)
			val := d.Get(key).(string)
			req.EmailAddresses = append(req.EmailAddresses, val)
		}
	}
	ipnum := d.Get("san_ip.#").(int)
	if ipnum > 0 {
		ipList := make([]string, 0, ipnum)
		for i := 0; i < ipnum; i++ {
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

	//Appending common name to the DNS names if it is not there
	if !sliceContains(req.DNSNames, commonName) {
		log.Printf("Adding CN %s to SAN because it wasn't included.", commonName)
		req.DNSNames = append(req.DNSNames, commonName)
	}

	log.Printf("Requested SAN: %s", req.DNSNames)

	if origin != csrService {
		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
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
	// setting by default a value if not set
	if _, ok := d.GetOk("expiration_window"); !ok {
		d.Set("expiration_window", expirationWindow)
	}

	if ttl, ok := d.GetOk("valid_days"); ok {

		validity := ttl.(int)
		validity = validity * 24
		expiration_window := d.Get("expiration_window").(int)

		if validity < expiration_window {
			if err = d.Set("expiration_window", validity); err != nil {
				return fmt.Errorf("error setting expiration_window: %s", err)
			}
		}

		req.ValidityHours = validity
		issuer_hint := d.Get("issuer_hint").(string)
		req.IssuerHint = getIssuerHint(issuer_hint)

	}

	log.Println("Making certificate request")
	err = cl.GenerateRequest(nil, req)
	if err != nil {
		return err
	}

	requestID, err := cl.RequestCertificate(req)
	if err != nil {
		return err
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		//TODO: make timeout configurable
		Timeout: 180 * time.Second,
	}

	if origin == csrService {
		if pass, ok := d.GetOk("key_password"); ok {
			pickupReq.KeyPassword = pass.(string)
		}

		//for tpp we should set FetchPrivateKey = true
		if cl.GetType() == endpoint.ConnectorTypeTPP {
			pickupReq.FetchPrivateKey = true
		}

	}

	err = d.Set("certificate_dn", requestID)
	if err != nil {
		return err
	}

	if cl.GetType() == endpoint.ConnectorTypeTPP {
		log.Println("Waiting 2 seconds as workaround for VEN-46960")
		time.Sleep(2 * time.Second)
	}

	pcc, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return err
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
	if err = d.Set("certificate", pcc.Certificate); err != nil {
		return fmt.Errorf("Error setting certificate: %s", err)
	}
	log.Println("Certificate set to ", pcc.Certificate)

	if err = d.Set("chain", strings.Join((pcc.Chain), "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
	}
	log.Println("Certificate chain set to", pcc.Chain)

	d.SetId(req.PickupID)
	log.Println("Setting up private key")

	KeyPassword := d.Get("key_password").(string)

	privKey := pcc.PrivateKey
	// for locally generated ECDSA private keys we get PKCS1 format, in other cases we get PKCS8
	if !(origin != csrService && keyType == "ECDSA") {
		privKey, err = util.DecryptPkcs8PrivateKey(pcc.PrivateKey, KeyPassword)
		if err != nil {
			return err
		}
	}

	certPkcs12, err := AsPKCS12(pcc.Certificate, privKey, pcc.Chain, KeyPassword)

	if err != nil {
		return err
	}

	s := base64.StdEncoding.EncodeToString(certPkcs12)
	if err = d.Set("pkcs12", s); err != nil {
		return fmt.Errorf("error setting pkcs12: %s", err)
	}

	return d.Set("private_key_pem", pcc.PrivateKey)
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
	var chain_list = []*x509.Certificate{}
	for _, chain_cert := range chain {
		crt, _ := pem.Decode([]byte(chain_cert))
		cert, err := x509.ParseCertificate(crt.Bytes)
		if err != nil {
			return nil, fmt.Errorf("chain certificate parse error")
		}
		chain_list = append(chain_list, cert)
	}

	// key?
	p, _ = pem.Decode([]byte(privateKey))
	if p == nil {
		return nil, fmt.Errorf("missing private key PEM")
	}
	var privDER []byte
	if x509.IsEncryptedPEMBlock(p) {
		privDER, err = x509.DecryptPEMBlock(p, []byte(keyPassword))
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

	bytes, err := pkcs12.Encode(rand.Reader, privKey, cert, chain_list, keyPassword)
	if err != nil {
		return nil, fmt.Errorf("encode error: %s", err)
	}

	return bytes, nil
}
func resourceVenafiCertificateImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	if id == "" {
		return nil, fmt.Errorf("the id is empty")
	}

	parameters := strings.Split(id, ",")

	if len(parameters) < 2 {
		return nil, fmt.Errorf("there are missing attributes")
	}
	pickupID := parameters[0]
	keyPassword := parameters[1]
	if pickupID == "" {
		return nil, fmt.Errorf("empty pickupID")
	}
	if keyPassword == "" {
		return nil, fmt.Errorf("empty key-password")
	}

	cfg := meta.(*vcert.Config)
	zone := cfg.Zone
	if zone == "" {
		return nil, fmt.Errorf("zone cannot be empty when importing certificate")
	}

	cl, err := getConnection(meta)
	if err != nil {
		return nil, err
	}

	if cl.GetType() == endpoint.ConnectorTypeTPP {
		zone = buildAbsoluteZoneTPP(zone)
		pickupID = fmt.Sprintf("%s\\%s", zone, pickupID)
	}

	pickupReq := fillRetrieveRequest(pickupID, keyPassword, cl.GetType())

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

	err = fillSchemaProperties(d, data, certMetadata, pickupID, keyPassword, cl.GetType())
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func fillRetrieveRequest(id string, p string, c endpoint.ConnectorType) *certificate.Request {
	pickupReq := &certificate.Request{}
	pickupReq.Timeout = 180 * time.Second
	pickupReq.PickupID = id
	pickupReq.KeyPassword = p

	if c == endpoint.ConnectorTypeTPP {
		pickupReq.FetchPrivateKey = true
	}
	return pickupReq
}

func fillSchemaProperties(d *schema.ResourceData, data *certificate.PEMCollection, certMetadata *certificate.CertificateMetaData, id string, p string, c endpoint.ConnectorType) error {
	err := d.Set("certificate", data.Certificate)
	if err != nil {
		return err
	}

	err = d.Set("private_key_pem", data.PrivateKey)
	if err != nil {
		return err
	}

	err = d.Set("key_password", p)
	if err != nil {
		return err
	}

	err = d.Set("csr_origin", csrService)
	if err != nil {
		return err
	}

	if err = d.Set("chain", strings.Join(data.Chain, "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
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

	privDER, _ := pem.Decode([]byte(data.PrivateKey))
	key, _, err := pkcs8.ParsePrivateKey(privDER.Bytes, []byte(p))
	if err != nil {
		return err
	}

	var pemType string

	switch keyValue := key.(type) {
	case *rsa.PrivateKey:
		err = d.Set("rsa_bits", keyValue.N.BitLen())
		if err != nil {
			return err
		}
		err = d.Set("ecdsa_curve", "P521")
		if err != nil {
			return err
		}
		err = d.Set("algorithm", "RSA")
		if err != nil {
			return err
		}
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		if c == endpoint.ConnectorTypeCloud {
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
		err = d.Set("algorithm", "ECDSA")
		if err != nil {
			return err
		}
		pemType = "EC PRIVATE KEY"
	default:
		return fmt.Errorf("failed to determine private key type")
	}

	if c == endpoint.ConnectorTypeTPP {
		ipAddresses := IPArrayToStringArray(cert.IPAddresses)
		err = d.Set("san_ip", ipAddresses)
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

	duration := cert.NotAfter.Sub(cert.NotBefore)
	validDays := int64(math.Floor(duration.Hours() / 24))
	err = d.Set("valid_days", validDays)
	if err != nil {
		return err
	}

	privateKeyBytes, err := pkcs8.MarshalPrivateKey(key, nil, nil)
	if err != nil {
		return err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: privateKeyBytes})
	certPkcs12, err := AsPKCS12(data.Certificate, string(pemBytes), data.Chain, p)
	if err != nil {
		return err
	}
	s := base64.StdEncoding.EncodeToString(certPkcs12)

	err = d.Set("pkcs12", s)
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
