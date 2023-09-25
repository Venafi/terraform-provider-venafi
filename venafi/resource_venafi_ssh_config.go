package venafi

import (
	"context"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceVenafiSshConfig() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVenafiSshConfigCreate,
		ReadContext:   resourceVenafiSshConfigRead,
		DeleteContext: resourceVenafiSshConfigDelete,

		Schema: map[string]*schema.Schema{
			"template": {
				Type:        schema.TypeString,
				Description: "The certificate issuing template",
				ForceNew:    true,
				Required:    true,
			},
			"ca_public_key": {
				Type:        schema.TypeString,
				Description: "The template's CA PublicKey",
				Computed:    true,
			},
			"principals": {
				Type:        schema.TypeList,
				Description: "The requested principals.",
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceVenafiSshConfigCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cl, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	template := d.Get("template").(string)
	req := &certificate.SshCaTemplateRequest{}
	req.Template = template

	conf, err := cl.RetrieveSshConfig(req)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(template)

	err = d.Set("ca_public_key", conf.CaPublicKey)

	if err != nil {
		return diag.FromErr(err)
	}

	if conf.Principals != nil {
		err = d.Set("principals", conf.Principals)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceVenafiSshConfigRead(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {

	principalsUntyped, ok := d.GetOk("principals")
	if !ok {
		d.SetId("")
		return nil
	}
	principals, ok := principalsUntyped.([]interface{})
	if !ok {
		d.SetId("")
		return nil
	}

	if len(principals) <= 0 {
		d.SetId("")
		return nil
	}

	for _, principal := range principals {
		principalString, ok := principal.(string)
		if !ok {
			d.SetId("")
			return nil
		}
		if principalString == "" {
			d.SetId("")
			return nil
		}
	}
	return nil
}

func resourceVenafiSshConfigDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}
