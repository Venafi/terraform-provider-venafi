package venafi

import (
	"fmt"
	"time"

	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/Venafi/vcert"
	vcertificate "github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"log"
	"net"
	"strings"
)

func resourceVenafiCertificate() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiCertificateCreate,
		Read:   resourceVenafiCertificateRead,
		Delete: resourceVenafiCertificateDelete,

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
			"store_pkey": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: `Set it to true to store certificates privates key in certificate fields`,
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

	id, err := cl.RequestCertificate(certReq, "")
	if err != nil {
		return err
	}

	certReq.PickupID = id
	var cert *vcertificate.PEMCollection

	retryerr := resource.Retry(time.Duration(300)*time.Second, func() *resource.RetryError {
		cert, err = cl.RetrieveCertificate(certReq)
		if err != nil {
			_, pending := err.(endpoint.ErrCertificatePending)
			_, timeout := err.(endpoint.ErrRetrieveCertificateTimeout)

			if pending || timeout {
				return resource.RetryableError(fmt.Errorf("certificate issue pending with id %s", id))
			} else {
				return resource.NonRetryableError(err)
			}

		}

		return nil
	})

	if retryerr != nil {
		return retryerr
	}

	if err = d.Set("certificate", cert.Certificate); err != nil {
		return fmt.Errorf("Error setting certificate: %s", err)
	}
	log.Println("Certificate set to ", cert)

	if err = d.Set("chain", strings.Join((cert.Chain), "")); err != nil {
		return fmt.Errorf("error setting chain: %s", err)
	}
	log.Println("Certificate chain set to", cert.Chain)

	d.SetId(id)
	return nil
}

func resourceVenafiCertificateRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}
func resourceVenafiCertificateDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func createVenafiCSR(d *schema.ResourceData) (*vcertificate.Request, error) {

	req := &vcertificate.Request{}

	//Configuring keys
	const defaultKeySize = 2048
	var (
		err         error
		keySize     int
		keyPassword string
	)
	if rsabits, ok := d.GetOk("rsa_bits"); ok {
		keySize = rsabits.(int)
	}

	keyCurve := d.Get("ecdsa_curve").(string)
	keyType := d.Get("algorithm").(string)

	log.Printf("%s,%s,%s", keyPassword, keyCurve, keyType)

	if pass, ok := d.GetOk("key_password"); ok {
		keyPassword = pass.(string)
		req.KeyPassword = keyPassword
	}

	if keyType == "RSA" || len(keyType) == 0 {
		//If not set setting key size to 2048 if not set or set less than 2048
		switch {
		case keySize == 0:
			req.KeyLength = defaultKeySize
		case keySize > defaultKeySize:
			req.KeyLength = keySize
		default:
			log.Printf("Key Size is less than %d, setting it to %d", defaultKeySize, defaultKeySize)
			req.KeyLength = defaultKeySize
		}
	} else if keyType == "ECDSA" {
		req.KeyType = vcertificate.KeyTypeECDSA
		switch {
		case len(keyCurve) == 0 || keyCurve == "P224":
			req.KeyCurve = vcertificate.EllipticCurveP224
		case keyCurve == "P256":
			req.KeyCurve = vcertificate.EllipticCurveP256
		case keyCurve == "P384":
			req.KeyCurve = vcertificate.EllipticCurveP384
		case keyCurve == "P521":
			req.KeyCurve = vcertificate.EllipticCurveP521
		}

	} else {
		return req, fmt.Errorf("Can't determine key algorithm %s", keyType)
	}

	//Setting up Subject
	commonName := d.Get("common_name").(string)
	//Adding alt names if exists
	dnsnum := d.Get("san_dns.#").(int)
	if dnsnum > 0 {
		req.DNSNames = make([]string, 0, dnsnum)
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
		req.EmailAddresses = make([]string, 0, emailnum)
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
		req.IPAddresses = make([]net.IP, 0, len(ipList))
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
	case vcertificate.KeyTypeECDSA:
		req.PrivateKey, err = vcertificate.GenerateECDSAPrivateKey(req.KeyCurve)
	case vcertificate.KeyTypeRSA:
		req.PrivateKey, err = vcertificate.GenerateRSAPrivateKey(req.KeyLength)
	default:
		return nil, fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
	}

	//Setting up CSR
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = req.Subject
	certificateRequest.DNSNames = req.DNSNames
	certificateRequest.EmailAddresses = req.EmailAddresses
	certificateRequest.IPAddresses = req.IPAddresses
	certificateRequest.Attributes = req.Attributes

	/* TODO:
	zoneConfig, err = cs.Conn.ReadZoneConfiguration(cf.Zone)
	zoneConfig.UpdateCertificateRequest(req)
		...should happen somewhere here before CSR is signed */

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, req.PrivateKey)

	req.CSR = csr

	req.CSR = pem.EncodeToMemory(vcertificate.GetCertificateRequestPEMBlock(req.CSR))

	pk, err := getPrivateKeyPEMBock(req.PrivateKey)
	if err != nil {
		return req, fmt.Errorf("error generating key: %s", err)
	}

	storePkey := d.Get("store_pkey").(bool)
	if storePkey {
		d.Set("private_key_pem", string(pem.EncodeToMemory(pk)))
	}

	return req, nil
}
