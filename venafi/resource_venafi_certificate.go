package venafi

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"net"
	"software.sslmate.com/src/go-pkcs12"
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
				Default:     168,
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
				Description: "The desired certificate validity",
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
	//venafi := meta.(*VenafiClient)
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

		cfg := meta.(*vcert.Config)
		cl, err := vcert.NewClient(cfg)
		if err != nil {
			log.Printf(messageVenafiClientInitFailed + err.Error())
			return false, err
		}

		if origin == "service" && cl.GetType() == endpoint.ConnectorTypeCloud {
			keyStr, err := util.DecryptPkcs8PrivateKey(pkUntyped.(string), d.Get("key_password").(string))
			if err != nil {
				return false, err
			}
			pk = []byte(keyStr)
		} else {
			pk, err = getPrivateKey([]byte(pkUntyped.(string)), d.Get("key_password").(string))
			if err != nil {
				return false, fmt.Errorf("error getting key: %s", err)
			}
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
	if origin == csrService && cl.GetType() == endpoint.ConnectorTypeCloud {
		privKey, err = util.DecryptPkcs8PrivateKey(pcc.PrivateKey, KeyPassword)
		if err != nil {
			return err
		}
	}

	pkcs12_cert, err := AsPKCS12(pcc.Certificate, privKey, pcc.Chain, KeyPassword)

	if err != nil {
		return err
	}

	s := base64.StdEncoding.EncodeToString(pkcs12_cert)
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

	pickupReq := fillRetrieveRequest(zone, pickupID, cl.GetType())
	pickupReq.KeyPassword = keyPassword

	data, err := cl.RetrieveCertificate(pickupReq)

	if err != nil {
		return nil, err
	}

	err = fillSchemaProperties(d, data, pickupID, keyPassword, cl.GetType())

	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func fillSchemaProperties(d *schema.ResourceData, data *certificate.PEMCollection, id string, p string, c endpoint.ConnectorType) error {
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

	err = d.Set("csr_origin", "service")
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

	err = d.Set("algorithm", cert.PublicKeyAlgorithm.String())
	if err != nil {
		return err
	}

	err = d.Set("certificate_dn", id)
	if err != nil {
		return err
	}

	privKey := data.PrivateKey
	if c == endpoint.ConnectorTypeCloud {
		privKey, err = util.DecryptPkcs8PrivateKey(data.PrivateKey, p)
		if err != nil {
			return err
		}
	} else {
		// Our connector is for TPP
		ipAddresses := IPArrayToStringArray(cert.IPAddresses)
		err = d.Set("san_ip", ipAddresses)
		if err != nil {
			return err
		}
	}

	certPkcs12, err := AsPKCS12(data.Certificate, privKey, data.Chain, p)
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

func fillRetrieveRequest(z, id string, c endpoint.ConnectorType) *certificate.Request {
	pickupReq := &certificate.Request{}
	pickupReq.FetchPrivateKey = true
	pickupReq.Timeout = 180 * time.Second

	if c == endpoint.ConnectorTypeTPP {
		zone := buildAbsoluteZoneTPP(z)
		pickupId := fmt.Sprintf("%s\\%s", zone, id)
		pickupReq.PickupID = pickupId
	} else {
		// We are building retrieveRequest for VaaS (Venafi Cloud)
		pickupReq.PickupID = id
	}

	return pickupReq
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
