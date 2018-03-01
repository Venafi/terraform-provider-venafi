package venafi

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/Venafi/govcert"
	uuid "github.com/satori/go.uuid"
)

func resourceVenafiCSR() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiCSRCreate,
		Read:   resourceVenafiCSRRead,
		Delete: resourceVenafiCSRDelete,

		Schema: map[string]*schema.Schema{
			"common_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
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
			"key_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
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
			"private_key_pem": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"csr_pem": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceVenafiCSRCreate(d *schema.ResourceData, meta interface{}) error {
	venafi := meta.(*VenafiClient)
	csrreq := &govcert.CSRReq{
		CommonName: d.Get("common_name").(string),
	}
	if ou, ok := d.GetOk("organizational_name"); ok {
		csrreq.OrganizationName = ou.(string)
	}
	if country, ok := d.GetOk("country"); ok {
		csrreq.OrganizationName = country.(string)
	}
	if state, ok := d.GetOk("state"); ok {
		csrreq.OrganizationName = state.(string)
	}
	if locality, ok := d.GetOk("locality"); ok {
		csrreq.OrganizationName = locality.(string)
	}
	if pass, ok := d.GetOk("key_password"); ok {
		csrreq.KeyPassword = pass.(string)
	}
	ounum := d.Get("organizational_unit.#").(int)
	if ounum > 0 {
		csrreq.OrganizationalUnit = make([]string, 0, ounum)
		for i := 0; i < ounum; i++ {
			key := fmt.Sprintf("organizational_unit.%d", i)
			vou := d.Get(key).(string)
			csrreq.OrganizationalUnit = append(csrreq.OrganizationalUnit, vou)
		}
	}
	dnsnum := d.Get("san_dns.#").(int)
	if dnsnum > 0 {
		csrreq.SanDNS = make([]string, 0, dnsnum)
		for i := 0; i < dnsnum; i++ {
			key := fmt.Sprintf("san_dns.%d", i)
			val := d.Get(key).(string)
			csrreq.SanDNS = append(csrreq.SanDNS, val)
		}
	}
	emailnum := d.Get("san_email.#").(int)
	if emailnum > 0 {
		csrreq.SanEmail = make([]string, 0, emailnum)
		for i := 0; i < emailnum; i++ {
			key := fmt.Sprintf("san_email.%d", i)
			val := d.Get(key).(string)
			csrreq.SanEmail = append(csrreq.SanEmail, val)
		}
	}
	ipnum := d.Get("san_ip.#").(int)
	if ipnum > 0 {
		csrreq.SanIP = make([]string, 0, ipnum)
		for i := 0; i < ipnum; i++ {
			key := fmt.Sprintf("san_ip.%d", i)
			val := d.Get(key).(string)
			csrreq.SanIP = append(csrreq.SanIP, val)
		}
	}

	resp, err := venafi.client.Do(csrreq)
	if err != nil {
		return err
	}
	// return resp

	pk, err := resp.ParseCSR()
	if err != nil {
		return err
	}

	u1,_ := uuid.NewV4()
	d.Set("private_key_pem", pk.PrivateKey)
	d.Set("csr_pem", pk.CSR)
	d.SetId(u1.String())

	return nil
}

func resourceVenafiCSRRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceVenafiCSRDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}
