package venafi

import (
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"log"
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
			"principal": &schema.Schema{
				Type:        schema.TypeList,
				Description: "The requested principals.",
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceVenafiSshConfigCreate(d *schema.ResourceData, meta interface{}) error {
	cfg := meta.(*vcert.Config)
	cl, err := vcert.NewClient(cfg)
	if err != nil {
		strErr := (err).Error()
		log.Printf("strErr: %s", strErr)
		if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: missing credentials" {
			log.Printf("Unable to build connector for %s: %s", cl.GetType(), err)
		} else if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: can't determine valid credentials set" {
			log.Printf("Unable to build connector for %s: %s", cl.GetType(), err)
		} else {
			log.Printf("Successfully built connector for %s", cl.GetType())
		}
	} else {
		log.Printf("Successfully built connector for %s", cl.GetType())
	}
	err = cl.Ping()
	if err != nil {
		log.Printf(messageVenafiPingFailed + err.Error())
		return fmt.Errorf("%s", messageVenafiPingFailed+err.Error())
	}
	log.Println(messageVenafiPingSucessfull)

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
		err = d.Set("principal", conf.Principals)
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

	capubstr := caPubKeyUntyped.(string)
	if capubstr == "" {
		return false, nil
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
