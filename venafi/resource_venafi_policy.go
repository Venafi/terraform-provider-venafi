package venafi

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"io/ioutil"
	"log"
	"os"
)

func resourceVenafiPolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceVenafiPolicyCreate,
		Read:   resourceVenafiPolicyRead,
		Delete: resourceVenafiPolicyDelete,
		Exists: resourceVenafiPolicyExists,

		Schema: map[string]*schema.Schema{
			"zone": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "zone name",
				ForceNew:    true,
			},
			"policy_specification_path": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "policy specification file path",
				ForceNew:    true,
			},
			"policy_specification": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
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
		return fmt.Errorf("zone name is empty")
	}

	path := d.Get("policy_specification_path").(string)
	if path == "" {
		return fmt.Errorf("policy specification path is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

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

	return []*schema.ResourceData{d}, nil
}
