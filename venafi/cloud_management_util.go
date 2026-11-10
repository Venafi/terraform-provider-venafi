package venafi

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

// Helpers shared by the venafi_cloud_provider and venafi_cloud_keystore resources

func getCloudProviderManager(ctx context.Context, meta interface{}, resourceName string) (endpoint.CloudProviderManager, endpoint.Connector, error) {
	connector, err := getConnection(ctx, meta)
	if err != nil {
		return nil, nil, err
	}
	manager, ok := connector.(endpoint.CloudProviderManager)
	if !ok {
		return nil, nil, platformNotSupportedError(connector, resourceName)
	}
	return manager, connector, nil
}

func getCloudKeystoreManager(ctx context.Context, meta interface{}, resourceName string) (endpoint.CloudKeystoreManager, endpoint.Connector, error) {
	connector, err := getConnection(ctx, meta)
	if err != nil {
		return nil, nil, err
	}
	manager, ok := connector.(endpoint.CloudKeystoreManager)
	if !ok {
		return nil, nil, platformNotSupportedError(connector, resourceName)
	}
	return manager, connector, nil
}

func platformNotSupportedError(connector endpoint.Connector, resourceName string) error {
	return fmt.Errorf("platform detected as [%s]. %s resource is only available for %s or %s",
		connector.GetType(), resourceName, endpoint.ConnectorTypeCloud, endpoint.ConnectorTypeNGTS)
}

// findCloudProviderByID returns the cloud provider with the given ID, or nil
// if there is none. The API cannot filter cloud providers by ID, so this lists
// them all.
func findCloudProviderByID(manager endpoint.CloudProviderManager, id string) (*domain.CloudProvider, error) {
	providers, err := manager.ListCloudProviders(domain.GetCloudProviderRequest{})
	if err != nil {
		return nil, err
	}
	for i := range providers {
		if providers[i].ID == id {
			return &providers[i], nil
		}
	}
	return nil, nil
}

// findCloudKeystoreByID returns the cloud keystore with the given ID, or nil
// if there is none
func findCloudKeystoreByID(manager endpoint.CloudKeystoreManager, id string) (*domain.CloudKeystore, error) {
	keystores, err := manager.ListCloudKeystores(domain.GetCloudKeystoreRequest{CloudKeystoreID: &id})
	if err != nil {
		return nil, err
	}
	for i := range keystores {
		if keystores[i].ID == id {
			return &keystores[i], nil
		}
	}
	return nil, nil
}

// singleBlock returns the attributes of a block declared with MaxItems: 1, or
// nil when the block is absent
func singleBlock(d *schema.ResourceData, key string) map[string]interface{} {
	blocks, ok := d.Get(key).([]interface{})
	if !ok || len(blocks) == 0 || blocks[0] == nil {
		return nil
	}
	block, _ := blocks[0].(map[string]interface{})
	return block
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// setAll stores the given values in the state, stopping at the first error
func setAll(d *schema.ResourceData, values map[string]interface{}) error {
	for key, value := range values {
		if err := d.Set(key, value); err != nil {
			return fmt.Errorf("failed to set %s: %w", key, err)
		}
	}
	return nil
}

// validateConfigBlocks checks that exactly the configuration block matching
// the resource type is set
func validateConfigBlocks(resource string, blocksByType map[string]string, resourceType string, isSet func(block string) bool) error {
	expected, ok := blocksByType[resourceType]
	if !ok {
		// the type itself is checked by its ValidateFunc; it can also still be
		// unknown at plan time
		return nil
	}
	if !isSet(expected) {
		return fmt.Errorf("a %s of type %s requires a %q block", resource, resourceType, expected)
	}
	for _, block := range blocksByType {
		if block != expected && isSet(block) {
			return fmt.Errorf("a %s of type %s cannot have a %q block", resource, resourceType, block)
		}
	}
	return nil
}
