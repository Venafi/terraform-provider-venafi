package venafi

import (
	"fmt"
	"net"
	"time"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/hashicorp/terraform/helper/schema"
	"log"
	"strings"
)

func resourceVenafiCertificate() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiCertificateCreate,
		Read:   resourceVenafiCertificateRead,
		Delete: resourceVenafiCertificateDelete,
		Update: resourceVenafiCertificateUpdate,

		Schema: map[string]*schema.Schema{
			"common_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"algorithm": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "RSA",
				Description: "RSA or ECDSA. RSA is default.",
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
				Default:     "P224",
			},

			"san_dns": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"san_email": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"san_ip": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"key_password": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				ForceNew:  true,
				Sensitive: true,
			},

			"private_key_pem": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"chain": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			"certificate": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"organizational_unit": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"organization_name": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"country": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"locality": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"csr_pem": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"certificate_dn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
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
	log.Println(messageVenafiPingSucessfull)

	certReq, err := createVenafiCSR(d)
	if err != nil {
		return err
	}

	log.Println("Making certificate request")
	err = cl.GenerateRequest(nil, certReq)
	if err != nil {
		return err
	}

	requestID, err := cl.RequestCertificate(certReq, "")
	if err != nil {
		return err
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		//TODO: make timeout configurable
		Timeout: 180 * time.Second,
	}
	d.Set("certificate_dn", requestID)

	//Workaround for VEN-46960
	time.Sleep(2 * time.Second)

	pcc, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return err
	}

	if pass, ok := d.GetOk("key_password"); ok {
		pcc.AddPrivateKey(certReq.PrivateKey, []byte(pass.(string)))
	} else {
		pcc.AddPrivateKey(certReq.PrivateKey, []byte(""))
	}

	if err = d.Set("certificate", pcc.Certificate); err != nil {
		return fmt.Errorf("Error setting certificate: %s", err)
	}
	log.Println("Certificate set to ", pcc.Certificate)

	if err = d.Set("chain", strings.Join((pcc.Chain), "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
	}
	log.Println("Certificate chain set to", pcc.Chain)

	d.SetId(certReq.PickupID)
	log.Println("Setting up private key")
	d.Set("private_key_pem", pcc.PrivateKey)
	return nil
}

func resourceVenafiCertificateRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}
func resourceVenafiCertificateDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func resourceVenafiCertificateUpdate(d *schema.ResourceData, meta interface{}) error {
	//TODO: Implement renew here
	log.Printf("Renewing certificate\n")
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
	log.Println(messageVenafiPingSucessfull)

	requestID := d.Get("certificate_dn").(string)
	renewReq := &certificate.RenewalRequest{
		CertificateDN: requestID,
	}
	newRequestID, err := cl.RenewCertificate(renewReq)
	if err != nil {
		return err
	}
	renewRetrieveReq := &certificate.Request{
		PickupID: newRequestID,
		Timeout:  180 * time.Second,
	}
	pcc, err := cl.RetrieveCertificate(renewRetrieveReq)
	if pass, ok := d.GetOk("key_password"); ok {
		pcc.AddPrivateKey(renewRetrieveReq.PrivateKey, []byte(pass.(string)))
	} else {
		pcc.AddPrivateKey(renewRetrieveReq.PrivateKey, []byte(""))
	}

	if err = d.Set("certificate", pcc.Certificate); err != nil {
		return fmt.Errorf("Error setting certificate: %s", err)
	}
	log.Println("Certificate set to ", pcc.Certificate)

	if err = d.Set("chain", strings.Join((pcc.Chain), "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
	}
	log.Println("Certificate chain set to", pcc.Chain)

	//d.SetId(newRequestID)
	log.Println("Setting up private key")
	d.Set("private_key_pem", pcc.PrivateKey)
	return nil
}

func createVenafiCSR(d *schema.ResourceData) (*certificate.Request, error) {

	req := &certificate.Request{
		CsrOrigin: certificate.LocalGeneratedCSR,
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
		switch {
		case keyCurve == "P224":
			req.KeyCurve = certificate.EllipticCurveP224
		case keyCurve == "P256":
			req.KeyCurve = certificate.EllipticCurveP256
		case keyCurve == "P384":
			req.KeyCurve = certificate.EllipticCurveP384
		case keyCurve == "P521":
			req.KeyCurve = certificate.EllipticCurveP521
		}

	} else {
		return req, fmt.Errorf("Can't determine key algorithm %s", keyType)
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
		return req, fmt.Errorf("no domains specified on certificate")
	}
	if len(commonName) == 0 && len(req.DNSNames) > 0 {
		commonName = req.DNSNames[0]
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
				return req, fmt.Errorf("invalid IP address %#v", ipList[i])
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

	switch req.KeyType {
	case certificate.KeyTypeECDSA:
		req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
	case certificate.KeyTypeRSA:
		req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
	default:
		return nil, fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
	}

	if err != nil {
		return req, fmt.Errorf("error generating key: %s", err)
	}

	return req, nil
}
