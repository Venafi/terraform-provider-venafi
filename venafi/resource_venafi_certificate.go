package venafi

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/Venafi/govcert"
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
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "RSA",
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
		},
	}
}

func resourceVenafiCertificateCreate(d *schema.ResourceData, meta interface{}) error {
	venafi := meta.(*VenafiClient)
	enrollreq := &govcert.EnrollReq{
		CommonName: d.Get("common_name").(string),
	}
	if pass, ok := d.GetOk("key_password"); ok {
		enrollreq.KeyPassword = pass.(string)
	}
	if rsabits, ok := d.GetOk("rsa_bits"); ok {
		enrollreq.KeySize = rsabits.(int)
	}
	if keycurve, ok := d.GetOk("ecdsa_curve"); ok {
		enrollreq.KeyCurve = keycurve.(string)
	}
	if v, ok := d.GetOk("algorithm"); ok {
		enrollreq.KeyType = v.(string)
	}

	dnsnum := d.Get("san_dns.#").(int)
	if dnsnum > 0 {
		enrollreq.Sans.DNS = make([]string, 0, dnsnum)
		for i := 0; i < dnsnum; i++ {
			key := fmt.Sprintf("san_dns.%d", i)
			val := d.Get(key).(string)
			enrollreq.Sans.DNS = append(enrollreq.Sans.DNS, val)
		}
	}
	emailnum := d.Get("san_email.#").(int)
	if emailnum > 0 {
		enrollreq.Sans.Email = make([]string, 0, emailnum)
		for i := 0; i < emailnum; i++ {
			key := fmt.Sprintf("san_email.%d", i)
			val := d.Get(key).(string)
			enrollreq.Sans.Email = append(enrollreq.Sans.Email, val)
		}
	}
	ipnum := d.Get("san_ip.#").(int)
	if ipnum > 0 {
		enrollreq.Sans.IP = make([]string, 0, ipnum)
		for i := 0; i < ipnum; i++ {
			key := fmt.Sprintf("san_ip.%d", i)
			val := d.Get(key).(string)
			enrollreq.Sans.IP = append(enrollreq.Sans.IP, val)
		}
	}
	enrollreq.Zone = venafi.zone

	// req, err := enrollreq.Request()
	// if err != nil {
	// 	return err
	// }

	resp, err := venafi.client.Do(enrollreq)
	if err != nil {
		return err
	}
	respmap, err := resp.JSONBody()
	if err != nil {
		return err
	}

	d.Set("private_key_pem", respmap["PrivateKey"].(string))
	if !resp.Pending() {
		d.Set("certificate", respmap["Certificate"].(string))
		d.Set("chain", strings.Join(stringArr(respmap["Chain"].([]interface{})), ""))
		id, err := resp.CompletedID()
		if err != nil {
			return err
		}
		d.SetId(id)
		return nil
	}
	id, err := resp.RequestID()
	if err != nil {
		return err
	}

	pickupreq := &govcert.PickupReq{
		PickupID: id,
	}

	retryerr := resource.Retry(time.Duration(300)*time.Second, func() *resource.RetryError {
		resp, err = venafi.client.Do(pickupreq)
		if err != nil {
			return resource.NonRetryableError(err)
		}
		if resp.Pending() {
			return resource.RetryableError(fmt.Errorf("Certificate Issue pending"))
		}

		return nil
	})

	if retryerr != nil {
		return retryerr
	}

	respmap, err = resp.JSONBody()
	if err != nil {
		return err
	}

	d.Set("certificate", respmap["Certificate"].(string))
	d.Set("chain", strings.Join(stringArr(respmap["Chain"].([]interface{})), ""))
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

func stringArr(d []interface{}) []string {
	r := []string{}
	for _, v := range d {
		r = append(r, v.(string))
	}
	return r
}
