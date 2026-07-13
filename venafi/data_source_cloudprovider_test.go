package venafi

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestDataSourceCloudProvider(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccCheckDataSourceCloudProviderConfig, vaasProvider, "GCP Cloud Provider Terraform"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.venafi_cloudprovider.test", "id"),
					resource.TestCheckResourceAttr(
						"data.venafi_cloudprovider.test", "name", "GCP Cloud Provider Terraform"),
					resource.TestCheckResourceAttr(
						"data.venafi_cloudprovider.test", "type", "GCP"),
					resource.TestCheckResourceAttr(
						"data.venafi_cloudprovider.test", "status", "VALIDATED"),
					resource.TestCheckResourceAttr(
						"data.venafi_cloudprovider.test", "status_details", ""),
					resource.TestCheckResourceAttr(
						"data.venafi_cloudprovider.test", "keystores_count", "1"),
				),
			},
			{
				Config:      fmt.Sprintf(testAccCheckDataSourceCloudProviderConfig, vaasProvider, ""),
				ExpectError: regexp.MustCompile("cloud provider name cannot be empty"),
			},
			{
				Config:      fmt.Sprintf(testAccCheckDataSourceCloudProviderConfig, vaasProvider, "error"),
				ExpectError: regexp.MustCompile(`error`),
			},
		},
	})
}

const testAccCheckDataSourceCloudProviderConfig = `
%s
data "venafi_cloud_provider" "test" {
  provider = "venafi.vaas"
  name = "%s"
}
`
