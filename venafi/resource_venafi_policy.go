package venafi

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"io/ioutil"
	"log"
	"regexp"
)

func resourceVenafiPolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiPolicyCreate,
		Read:   resourceVenafiPolicyRead,
		Delete: resourceVenafiPolicyDelete,
		Exists: resourceVenafiPolicyExists,

		Schema: map[string]*schema.Schema{
			"zone": {
				Type:        schema.TypeString,
				Description: "zone name",
				ForceNew:    true,
				Optional:    true,
			},
			"policy_specification": {
				Type:        schema.TypeString,
				Description: "policy specification",
				ForceNew:    true,
				Optional:    true,
			},
		},
		Importer: &schema.ResourceImporter{
			State: resourceVenafiPolicyImport,
		},
	}
}

func resourceVenafiPolicyCreate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("Creating policy\n")

	cl, err := getConnection(meta)
	if err != nil {
		return err
	}

	zoneName := d.Get("zone").(string)

	if zoneName == "" {
		return fmt.Errorf("zone is empty")
	}

	ps := d.Get("policy_specification").(string)
	if ps == "" {
		return fmt.Errorf("policy specification file is empty")
	}

	bytes := []byte(ps)

	var policySpecification policy.PolicySpecification
	err = json.Unmarshal(bytes, &policySpecification)
	if err != nil {
		return err
	}

	_, err = cl.SetPolicy(zoneName, &policySpecification)
	if err != nil {
		return err
	}

	d.SetId(zoneName)

	stringPS := string(bytes)

	err = d.Set("policy_specification", stringPS)

	if err != nil {
		return err
	}

	return nil
}

func resourceVenafiPolicyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	ps, ok := d.GetOk("policy_specification")

	if !ok {
		return false, nil
	}

	if ps == nil {
		return false, nil
	}

	data := []byte(ps.(string))

	var policySpecification policy.PolicySpecification
	err := json.Unmarshal(data, &policySpecification)
	if err != nil {
		return false, err
	}

	return true, nil

}

func resourceVenafiPolicyRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceVenafiPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func resourceVenafiPolicyImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	cl, err := getConnection(meta)

	if err != nil {
		return nil, err
	}

	log.Printf("Getting policy\n")

	ps, err := cl.GetPolicy(id)

	if err != nil {
		return nil, err
	}

	d.SetId(id)

	err = d.Set("zone", id)
	if err != nil {
		return nil, err
	}

	bytes, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return nil, err
	}

	stringPS := string(bytes)

	err = d.Set("policy_specification", stringPS)

	if err != nil {
		return nil, err
	}

	var byte []byte

	fileName := id

	regex, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return nil, err
	}

	fileName = regex.ReplaceAllString(fileName, "_")

	byte, err = json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return nil, err
	}

	fileName = fmt.Sprint(fileName, policy.JsonExtension)

	err = ioutil.WriteFile(fileName, byte, 0600)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
