package venafi

import (
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceVenafiSshConfig() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiSshConfigCreate,
		Read:   resourceVenafiSshConfigRead,
		Delete: resourceVenafiSshConfigDelete,
		Exists: resourceVenafiSshConfigExists,

		Schema: map[string]*schema.Schema{
			"template": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The certificate issuing template",
				ForceNew:    true,
				Required:    true,
			},
			"ca_public_key": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The template's CA PublicKey",
				Computed:    true,
			},
			"principals": &schema.Schema{
				Type:        schema.TypeList,
				Description: "The requested principals.",
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceVenafiSshConfigCreate(d *schema.ResourceData, meta interface{}) error {
	cl, err := getConnection(meta)
	template := d.Get("template").(string)
	req := &certificate.SshCaTemplateRequest{}
	req.Template = template

	conf, err := cl.RetrieveSshConfig(req)
	if err != nil {
		return err
	}
	d.SetId(template)

	err = d.Set("ca_public_key", conf.CaPublicKey)

	if err != nil {
		return err
	}

	if conf.Principals != nil {
		err = d.Set("principals", conf.Principals)
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceVenafiSshConfigExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	caPubKeyUntyped, ok := d.GetOk("public_key")
	if !ok {
		return false, nil
	}

	caPubKeyStr := caPubKeyUntyped.(string)
	if caPubKeyStr == "" {
		return false, nil
	}

	principalsUntyped, ok := d.GetOk("principals")
	principals, ok := principalsUntyped.([]interface{})
	if !ok {
		return false, nil
	}

	if len(principals) <= 0 {
		return false, nil
	}

	for _, principal := range principals {
		principalString, ok := principal.(string)
		if !ok {
			return false, nil
		}
		if principalString == "" {
			return false, nil
		}
	}

	return true, nil
}

func resourceVenafiSshConfigRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceVenafiSshConfigDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}
