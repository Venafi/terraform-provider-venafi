package venafi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/policy"
)

func resourceVenafiPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVenafiPolicyCreate,
		ReadContext:   resourceVenafiPolicyRead,
		DeleteContext: resourceVenafiPolicyDelete,

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
			StateContext: resourceVenafiPolicyImport,
		},
	}
}

func resourceVenafiPolicyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	tflog.Info(ctx, "Creating policy\n")

	cl, err := getConnection(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	zoneName := d.Get("zone").(string)

	if zoneName == "" {
		return buildStantardDiagError("zone is empty")
	}

	ps := d.Get("policy_specification").(string)
	if ps == "" {
		return buildStantardDiagError("policy specification file is empty")
	}

	bytes := []byte(ps)

	var policySpecification policy.PolicySpecification
	err = json.Unmarshal(bytes, &policySpecification)
	if err != nil {
		return diag.FromErr(err)
	}

	_, err = cl.SetPolicy(zoneName, &policySpecification)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(zoneName)

	stringPS := string(bytes)

	err = d.Set("policy_specification", stringPS)

	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceVenafiPolicyRead(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// verify if since policy have been update, if we need to update it in the state our delete it
	ps, ok := d.GetOk("policy_specification")

	if !ok {
		d.SetId("")
		return nil
	}

	if ps == nil {
		d.SetId("")
		return nil
	}

	data := []byte(ps.(string))

	var policySpecification policy.PolicySpecification
	err := json.Unmarshal(data, &policySpecification)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceVenafiPolicyDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

func resourceVenafiPolicyImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	cl, err := getConnection(ctx, meta)

	if err != nil {
		return nil, err
	}

	tflog.Info(ctx, "Getting policy\n")

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

	var data []byte

	fileName := id

	regex, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return nil, err
	}

	fileName = regex.ReplaceAllString(fileName, "_")

	data, err = json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return nil, err
	}

	fileName = fmt.Sprint(fileName, policy.JsonExtension)

	err = os.WriteFile(fileName, data, 0600)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
