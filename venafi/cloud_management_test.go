package venafi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/fake"
)

// fakeCloudConnector is an in-memory implementation of the cloud provider and
// keystore management interfaces. The rest of endpoint.Connector comes from
// vcert's fake connector.
type fakeCloudConnector struct {
	*fake.Connector
	// Terraform calls resources concurrently
	mu            sync.Mutex
	connectorType endpoint.ConnectorType
	providers     map[string]*domain.CloudProvider
	keystores     map[string]*domain.CloudKeystore
	nextID        int

	// validationResults are returned by successive ValidateCloudProvider
	// calls; the last one is repeated
	validationResults []domain.CloudProviderValidationResult
	validateCalls     int

	createdProvider  *domain.CreateCloudProviderRequest
	updatedProvider  *domain.UpdateCloudProviderRequest
	createdKeystore  *domain.CreateCloudKeystoreRequest
	updatedKeystore  *domain.UpdateCloudKeystoreRequest
	keystoresCreated int
}

func newFakeCloudConnector(connectorType endpoint.ConnectorType) *fakeCloudConnector {
	return &fakeCloudConnector{
		Connector:     fake.NewConnector(false, nil),
		connectorType: connectorType,
		providers:     map[string]*domain.CloudProvider{},
		keystores:     map[string]*domain.CloudKeystore{},
	}
}

func (f *fakeCloudConnector) GetType() endpoint.ConnectorType { return f.connectorType }

func (f *fakeCloudConnector) newID() string {
	f.nextID++
	return fmt.Sprintf("id-%d", f.nextID)
}

func (f *fakeCloudConnector) ListCloudProviders(filter domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]domain.CloudProvider, 0)
	for _, p := range f.providers {
		if strings.Contains(p.Name, filter.Name) {
			result = append(result, *copyProvider(p))
		}
	}
	return result, nil
}

// CreateCloudProvider stores the configuration the way the platform returns
// it: without the Azure secret, and with generated values
func (f *fakeCloudConnector) CreateCloudProvider(request domain.CreateCloudProviderRequest) (*domain.CloudProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createdProvider = &request
	p := &domain.CloudProvider{ID: f.newID(), Name: request.Name, Type: request.Type, Status: domain.CloudProviderStatusNotValidated}
	if request.AWS != nil {
		p.AWS = &domain.CloudProviderAWSConfiguration{AccountID: request.AWS.AccountID, Role: request.AWS.Role, ExternalID: "external-" + p.ID}
	}
	if request.Azure != nil {
		p.Azure = &domain.CloudProviderAzureConfiguration{ApplicationID: request.Azure.ApplicationID, DirectoryID: request.Azure.DirectoryID}
	}
	if request.GCP != nil {
		gcp := *request.GCP
		if gcp.AuthorizationMethod == domain.GCPAuthorizationMethodUnknown {
			gcp.AuthorizationMethod = domain.GCPAuthorizationMethodVenafiGeneratedKey
		}
		gcp.PublicKey = "public-key-" + p.ID
		p.GCP = &gcp
	}
	f.providers[p.ID] = p
	return copyProvider(p), nil
}

func copyProvider(p *domain.CloudProvider) *domain.CloudProvider {
	copied := *p
	if p.AWS != nil {
		aws := *p.AWS
		copied.AWS = &aws
	}
	if p.Azure != nil {
		azure := *p.Azure
		copied.Azure = &azure
	}
	if p.GCP != nil {
		gcp := *p.GCP
		copied.GCP = &gcp
	}
	return &copied
}

func (f *fakeCloudConnector) UpdateCloudProvider(request domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatedProvider = &request
	p, ok := f.providers[request.ID]
	if !ok {
		return nil, fmt.Errorf("cloud provider %s not found", request.ID)
	}
	if request.Name != nil {
		p.Name = *request.Name
	}
	// like the platform, a configuration change resets the validation status
	if request.AWS != nil && request.AWS.Role != nil && *request.AWS.Role != p.AWS.Role {
		p.AWS.Role = *request.AWS.Role
		p.Status = domain.CloudProviderStatusNotValidated
	}
	if request.Azure != nil {
		p.Azure.ApplicationID = *request.Azure.ApplicationID
		p.Azure.DirectoryID = *request.Azure.DirectoryID
		p.Status = domain.CloudProviderStatusNotValidated
	}
	// like the platform, workload identity fields that are not sent keep
	// their stored values
	if request.GCP != nil {
		keep := func(stored *string, update *string) {
			if update != nil && *update != "" {
				*stored = *update
			}
		}
		keep(&p.GCP.ProjectNumber, request.GCP.ProjectNumber)
		keep(&p.GCP.WorkloadIdentityPoolID, request.GCP.WorkloadIdentityPoolID)
		keep(&p.GCP.WorkloadIdentityPoolProviderID, request.GCP.WorkloadIdentityPoolProviderID)
		if request.GCP.AuthorizationMethod != domain.GCPAuthorizationMethodUnknown {
			p.GCP.AuthorizationMethod = request.GCP.AuthorizationMethod
		}
		p.Status = domain.CloudProviderStatusNotValidated
	}
	return copyProvider(p), nil
}

func (f *fakeCloudConnector) DeleteCloudProvider(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.providers[id]; !ok {
		return fmt.Errorf("cloud provider %s not found", id)
	}
	delete(f.providers, id)
	return nil
}

func (f *fakeCloudConnector) ValidateCloudProvider(id string) (*domain.CloudProviderValidationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := domain.CloudProviderValidationResult{Status: domain.CloudProviderStatusValidated}
	if len(f.validationResults) > 0 {
		i := f.validateCalls
		if i >= len(f.validationResults) {
			i = len(f.validationResults) - 1
		}
		result = f.validationResults[i]
	}
	f.validateCalls++
	if p, ok := f.providers[id]; ok {
		p.Status = result.Status
		p.StatusDetails = result.Details
	}
	return &result, nil
}

func (f *fakeCloudConnector) ListCloudKeystores(filter domain.GetCloudKeystoreRequest) ([]domain.CloudKeystore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]domain.CloudKeystore, 0)
	for _, k := range f.keystores {
		if filter.CloudKeystoreID == nil || *filter.CloudKeystoreID == k.ID {
			result = append(result, *k)
		}
	}
	return result, nil
}

func (f *fakeCloudConnector) CreateCloudKeystore(request domain.CreateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// like the platform, keystores need a validated provider; providers the
	// fake does not know about are accepted so tests can use any ID
	if p, ok := f.providers[request.CloudProviderID]; ok && p.Status != domain.CloudProviderStatusValidated {
		return nil, fmt.Errorf("cloud provider %s is not validated", p.Name)
	}
	f.createdKeystore = &request
	f.keystoresCreated++
	k := &domain.CloudKeystore{
		ID: f.newID(), Name: request.Name, Type: request.Type,
		CloudProviderID: request.CloudProviderID, CloudProviderName: "provider",
		ACM: request.ACM, AKV: request.AKV, GCM: request.GCM,
		// the platform defaults that apply when nothing is configured
		DiscoveryConfiguration: &domain.CloudDiscoveryConfiguration{IncludeExpiredCertificates: true},
	}
	applyDiscoveryOptions(k.DiscoveryConfiguration, request.Discovery)
	f.keystores[k.ID] = k
	copied := *k
	return &copied, nil
}

func (f *fakeCloudConnector) UpdateCloudKeystore(request domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatedKeystore = &request
	k, ok := f.keystores[request.ID]
	if !ok {
		return nil, fmt.Errorf("cloud keystore %s not found", request.ID)
	}
	if request.Name != nil {
		k.Name = *request.Name
	}
	applyDiscoveryOptions(k.DiscoveryConfiguration, request.Discovery)
	copied := *k
	return &copied, nil
}

func applyDiscoveryOptions(config *domain.CloudDiscoveryConfiguration, options *domain.CloudDiscoveryOptions) {
	if options == nil {
		return
	}
	if options.ScheduleSpecification != nil {
		config.ScheduleSpecification = *options.ScheduleSpecification
	}
	if options.IncludeExpiredCertificates != nil {
		config.IncludeExpiredCertificates = *options.IncludeExpiredCertificates
	}
	if options.IncludeRevokedCertificates != nil {
		config.IncludeRevokedCertificates = *options.IncludeRevokedCertificates
	}
}

func (f *fakeCloudConnector) DeleteCloudKeystore(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keystores[id]; !ok {
		return fmt.Errorf("cloud keystore %s not found", id)
	}
	delete(f.keystores, id)
	return nil
}

func (f *fakeCloudConnector) ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	return nil, nil
}

// applyConfig runs a plan and apply of the given configuration against the
// prior state, the way Terraform core does, and returns the new state
func applyConfig(t *testing.T, r *schema.Resource, state *terraform.InstanceState, raw map[string]interface{}, meta interface{}) *terraform.InstanceState {
	t.Helper()
	ctx := context.Background()

	// Terraform core sends the configuration as a typed value; providers read
	// it through ResourceData.GetRawConfig. Diff copies it from the prior state.
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	configVal, err := ctyjson.Unmarshal(b, r.CoreConfigSchema().ImpliedType())
	if err != nil {
		t.Fatalf("invalid configuration: %s", err)
	}
	if state == nil {
		state = &terraform.InstanceState{}
	}
	state.RawConfig = configVal

	diff, err := r.Diff(ctx, state, terraform.NewResourceConfigRaw(raw), meta)
	if err != nil {
		t.Fatalf("plan failed: %s", err)
	}
	if diff == nil {
		return state
	}
	newState, diags := r.Apply(ctx, state, diff, meta)
	if diags.HasError() {
		t.Fatalf("apply failed: %v", diags)
	}
	return newState
}

func planConfig(r *schema.Resource, state *terraform.InstanceState, raw map[string]interface{}, meta interface{}) (*terraform.InstanceDiff, error) {
	return r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(raw), meta)
}

func TestCloudProviderResourceLifecycle(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	config := map[string]interface{}{
		"name": "aws",
		"type": "AWS",
		"aws":  []interface{}{map[string]interface{}{"account_id": "123456789012", "role": "role-a"}},
	}
	state := applyConfig(t, r, nil, config, meta)

	if state.ID == "" || state.Attributes["status"] != "NOT_VALIDATED" {
		t.Fatalf("unexpected state after create: %v", state.Attributes)
	}
	created := connector.createdProvider
	if created == nil || created.AWS == nil || created.AWS.AccountID != "123456789012" || created.Type != domain.CloudProviderTypeAWS {
		t.Fatalf("unexpected create request: %+v", created)
	}

	// change only the name and role: the update must carry exactly those
	config["name"] = "aws-renamed"
	config["aws"] = []interface{}{map[string]interface{}{"account_id": "123456789012", "role": "role-b"}}
	state = applyConfig(t, r, state, config, meta)

	updated := connector.updatedProvider
	if updated == nil || updated.ID != state.ID || updated.Type != domain.CloudProviderTypeAWS {
		t.Fatalf("unexpected update request: %+v", updated)
	}
	if updated.Name == nil || *updated.Name != "aws-renamed" || updated.AWS == nil || *updated.AWS.Role != "role-b" || updated.TeamID != nil {
		t.Fatalf("unexpected update request: %+v", updated)
	}
	if state.Attributes["name"] != "aws-renamed" {
		t.Fatalf("expected the new name in state, got %v", state.Attributes)
	}

	// changing the account forces a new resource
	config["aws"] = []interface{}{map[string]interface{}{"account_id": "999999999999", "role": "role-b"}}
	diff, err := planConfig(r, state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.RequiresNew() {
		t.Fatalf("expected a change of AWS account to require a new resource")
	}

	// a provider deleted outside of Terraform is removed from the state
	delete(connector.providers, state.ID)
	d := r.Data(state)
	if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.Id() != "" {
		t.Fatalf("expected the deleted provider to be removed from state")
	}
}

func TestCloudProviderResourceRejectsMismatchedBlock(t *testing.T) {
	r := resourceVenafiCloudProvider()
	meta := &ProviderConfig{VCertClient: newFakeCloudConnector(endpoint.ConnectorTypeNGTS)}

	_, err := planConfig(r, nil, map[string]interface{}{
		"name": "azure",
		"type": "AZURE",
		"aws":  []interface{}{map[string]interface{}{"account_id": "123456789012", "role": "role"}},
	}, meta)
	if err == nil || !strings.Contains(err.Error(), `requires a "azure" block`) {
		t.Fatalf("expected a missing block error, got %v", err)
	}
}

func TestCloudProviderResourceRejectsOtherPlatforms(t *testing.T) {
	r := resourceVenafiCloudProvider()
	meta := &ProviderConfig{VCertClient: fake.NewConnector(false, nil)}

	d := r.TestResourceData()
	d.SetId("p1")
	diags := r.ReadContext(context.Background(), d, meta)
	if !diags.HasError() || !strings.Contains(diags[0].Summary, "venafi_cloud_provider resource is only available for") {
		t.Fatalf("expected a platform not supported error, got %v", diags)
	}
}

func TestCloudProviderResourceAzureUpdateSendsSecret(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeCloud)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	config := map[string]interface{}{
		"name":  "azure",
		"type":  "AZURE",
		"team":  "Cloud Admins",
		"azure": []interface{}{map[string]interface{}{"application_id": "app", "directory_id": "dir", "secret": "s1"}},
	}
	state := applyConfig(t, r, nil, config, meta)
	if connector.createdProvider.TeamID != "Cloud Admins" {
		t.Fatalf("expected the team to be passed through, got %+v", connector.createdProvider)
	}

	config["azure"] = []interface{}{map[string]interface{}{"application_id": "app2", "directory_id": "dir", "secret": "s1"}}
	applyConfig(t, r, state, config, meta)

	updated := connector.updatedProvider
	if updated == nil || updated.Azure == nil || *updated.Azure.ApplicationID != "app2" || updated.Azure.Secret != "s1" {
		t.Fatalf("expected the azure update to carry the secret, got %+v", updated)
	}
}

func TestCloudKeystoreResourceLifecycle(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudKeystore()

	config := map[string]interface{}{
		"name":                         "acm",
		"type":                         "ACM",
		"cloud_provider_id":            "p1",
		"acm":                          []interface{}{map[string]interface{}{"region": "us-east-1"}},
		"include_expired_certificates": false,
	}
	state := applyConfig(t, r, nil, config, meta)

	created := connector.createdKeystore
	if created == nil || created.ACM == nil || created.ACM.Region != "us-east-1" || created.CloudProviderID != "p1" {
		t.Fatalf("unexpected create request: %+v", created)
	}
	// false was configured explicitly, so it must be sent; revoked was not configured
	if created.Discovery == nil || created.Discovery.IncludeExpiredCertificates == nil || *created.Discovery.IncludeExpiredCertificates ||
		created.Discovery.IncludeRevokedCertificates != nil || created.Discovery.ScheduleSpecification != nil {
		t.Fatalf("unexpected discovery options: %+v", created.Discovery)
	}
	if state.Attributes["include_revoked_certificates"] != "false" || state.Attributes["cloud_provider_name"] != "provider" {
		t.Fatalf("expected computed values in state, got %v", state.Attributes)
	}

	// a schedule change is an in-place update carrying only the schedule
	config["discovery_schedule"] = "00 03 * * *"
	state = applyConfig(t, r, state, config, meta)

	updated := connector.updatedKeystore
	if updated == nil || updated.Name != nil || updated.Discovery == nil || updated.Discovery.ScheduleSpecification == nil ||
		*updated.Discovery.ScheduleSpecification != "00 03 * * *" || updated.Discovery.IncludeExpiredCertificates != nil {
		t.Fatalf("unexpected update request: %+v", updated)
	}
	if state.Attributes["discovery_schedule"] != "00 03 * * *" {
		t.Fatalf("expected the schedule in state, got %v", state.Attributes)
	}

	// re-applying the same configuration makes no changes
	connector.updatedKeystore = nil
	diff, err := planConfig(r, state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("expected no changes, got %+v", diff)
	}

	// the keystore configuration cannot be updated, so a new region replaces it
	config["acm"] = []interface{}{map[string]interface{}{"region": "eu-west-1"}}
	diff, err = planConfig(r, state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.RequiresNew() {
		t.Fatalf("expected a change of region to require a new resource")
	}

	d := r.Data(state)
	if diags := r.DeleteContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if len(connector.keystores) != 0 {
		t.Fatalf("expected the keystore to be deleted")
	}
}

func TestCloudKeystoreResourceImport(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeCloud)
	connector.keystores["k1"] = &domain.CloudKeystore{
		ID: "k1", Name: "vault", Type: domain.CloudKeystoreTypeAKV, CloudProviderID: "p1", CloudProviderName: "azure",
		AKV:                    &domain.CloudKeystoreAKVConfiguration{KeyVaultName: "prod-vault"},
		DiscoveryConfiguration: &domain.CloudDiscoveryConfiguration{ScheduleSpecification: "00 03 * * *", IncludeRevokedCertificates: true},
	}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudKeystore()

	d := r.TestResourceData()
	d.SetId("k1")
	if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	// everything needed to manage the keystore is read back, so the matching
	// configuration plans no changes after an import
	state := d.State()
	diff, err := planConfig(r, state, map[string]interface{}{
		"name":                         "vault",
		"type":                         "AKV",
		"cloud_provider_id":            "p1",
		"akv":                          []interface{}{map[string]interface{}{"key_vault_name": "prod-vault"}},
		"discovery_schedule":           "00 03 * * *",
		"include_revoked_certificates": true,
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("expected no changes after import, got %+v", diff)
	}
}

func TestCloudProviderResourceReadsConfiguration(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	config := map[string]interface{}{
		"name": "gcp",
		"type": "GCP",
		"gcp":  []interface{}{map[string]interface{}{"service_account_email": "sa@p.iam.gserviceaccount.com"}},
	}
	state := applyConfig(t, r, nil, config, meta)

	// generated and defaulted values are exposed
	if state.Attributes["gcp.0.public_key"] != "public-key-"+state.ID || state.Attributes["gcp.0.authorization_method"] != "VENAFI_GENERATED_KEY" {
		t.Fatalf("expected the generated configuration in state, got %v", state.Attributes)
	}

	// and do not cause a diff against a configuration that leaves them out
	diff, err := planConfig(r, state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("expected no changes, got %+v", diff)
	}
}

func TestCloudProviderResourceDetectsConfigurationDrift(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeCloud)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	config := map[string]interface{}{
		"name": "aws",
		"type": "AWS",
		"team": "Cloud Admins",
		"aws":  []interface{}{map[string]interface{}{"account_id": "123456789012", "role": "role-a"}},
	}
	state := applyConfig(t, r, nil, config, meta)
	if state.Attributes["aws.0.external_id"] != "external-"+state.ID {
		t.Fatalf("expected the external ID in state, got %v", state.Attributes)
	}

	// someone changes the role outside of Terraform
	connector.providers[state.ID].AWS.Role = "role-changed"
	d := r.Data(state)
	if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	diff, err := planConfig(r, d.State(), config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff == nil || diff.Attributes["aws.0.role"] == nil || diff.Attributes["aws.0.role"].Old != "role-changed" || diff.Attributes["aws.0.role"].New != "role-a" {
		t.Fatalf("expected the role change to be planned back, got %+v", diff)
	}
}

func TestCloudProviderResourceKeepsAzureSecret(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	config := map[string]interface{}{
		"name":  "azure",
		"type":  "AZURE",
		"azure": []interface{}{map[string]interface{}{"application_id": "app", "directory_id": "dir", "secret": "s1"}},
	}
	state := applyConfig(t, r, nil, config, meta)

	d := r.Data(state)
	if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.State().Attributes["azure.0.secret"] != "s1" {
		t.Fatalf("expected the secret to be kept in state, got %v", d.State().Attributes)
	}
	diff, err := planConfig(r, d.State(), config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("expected no changes, got %+v", diff)
	}
}

func TestCloudProviderResourceImport(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{
		ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS, Status: domain.CloudProviderStatusValidated,
		AWS: &domain.CloudProviderAWSConfiguration{AccountID: "123456789012", Role: "role", ExternalID: "ext"},
	}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProvider()

	d := r.TestResourceData()
	d.SetId("p1")
	if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	diff, err := planConfig(r, d.State(), map[string]interface{}{
		"name": "aws",
		"type": "AWS",
		"aws":  []interface{}{map[string]interface{}{"account_id": "123456789012", "role": "role"}},
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("expected no changes after import, got %+v", diff)
	}
}

func shortValidationRetries(t *testing.T) {
	t.Helper()
	interval := cloudProviderValidationRetryInterval
	cloudProviderValidationRetryInterval = time.Millisecond
	t.Cleanup(func() { cloudProviderValidationRetryInterval = interval })
}

func TestCloudProviderValidationRetriesUntilValidated(t *testing.T) {
	shortValidationRetries(t)
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS}
	connector.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
		{Status: domain.CloudProviderStatusValidated},
	}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProviderValidation()

	state := applyConfig(t, r, nil, map[string]interface{}{"cloud_provider_id": "p1"}, meta)

	if connector.validateCalls != 3 {
		t.Fatalf("expected 3 validation attempts, got %d", connector.validateCalls)
	}
	if state.ID != "p1" || state.Attributes["status"] != "VALIDATED" {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestCloudProviderValidationTimesOut(t *testing.T) {
	shortValidationRetries(t)
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS}
	connector.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
	}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProviderValidation()
	timeout := 200 * time.Millisecond
	r.Timeouts.Create = &timeout

	ctx := context.Background()
	diff, err := r.Diff(ctx, nil, terraform.NewResourceConfigRaw(map[string]interface{}{"cloud_provider_id": "p1"}), meta)
	if err != nil {
		t.Fatal(err)
	}
	state, diags := r.Apply(ctx, nil, diff, meta)

	if !diags.HasError() || !strings.Contains(diags[0].Summary, "was not validated within 200ms: role cannot be assumed") {
		t.Fatalf("expected a timeout error with the details, got %v", diags)
	}
	if connector.validateCalls < 2 {
		t.Fatalf("expected validation to be retried, got %d attempts", connector.validateCalls)
	}
	// nothing is stored, so the next apply validates again
	if state != nil && state.ID != "" {
		t.Fatalf("expected no state, got %+v", state)
	}
}

func TestCloudProviderValidationReadDetectsLostValidation(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProviderValidation()
	state := applyConfig(t, r, nil, map[string]interface{}{"cloud_provider_id": "p1"}, meta)

	read := func() string {
		d := r.Data(state)
		if diags := r.ReadContext(context.Background(), d, meta); diags.HasError() {
			t.Fatalf("read failed: %v", diags)
		}
		return d.Id()
	}

	if read() != "p1" {
		t.Fatalf("expected a validated provider to stay in state")
	}
	// a configuration change on the platform resets the status
	connector.providers["p1"].Status = domain.CloudProviderStatusNotValidated
	if read() != "" {
		t.Fatalf("expected the validation to be removed from state once the provider is no longer validated")
	}
	delete(connector.providers, "p1")
	if read() != "" {
		t.Fatalf("expected the validation to be removed from state once the provider is gone")
	}
}

func TestCloudProviderValidationTriggersForceRevalidation(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{ID: "p1", Name: "azure", Type: domain.CloudProviderTypeAzure}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProviderValidation()

	config := map[string]interface{}{"cloud_provider_id": "p1", "triggers": map[string]interface{}{"secret_version": "1"}}
	state := applyConfig(t, r, nil, config, meta)

	config["triggers"] = map[string]interface{}{"secret_version": "2"}
	diff, err := planConfig(r, state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.RequiresNew() {
		t.Fatalf("expected a trigger change to validate again")
	}
}

func TestCloudResourcesDeleteObjectsAlreadyGone(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	meta := &ProviderConfig{VCertClient: connector}

	for _, r := range []*schema.Resource{resourceVenafiCloudProvider(), resourceVenafiCloudKeystore()} {
		d := r.TestResourceData()
		d.SetId("deleted-outside-terraform")
		if diags := r.DeleteContext(context.Background(), d, meta); diags.HasError() {
			t.Fatalf("delete of an object that is already gone failed: %v", diags)
		}
		if d.Id() != "" {
			t.Fatalf("expected the object to be removed from state")
		}
	}
}

func TestCloudProviderValidationImportExplainsUnvalidatedProvider(t *testing.T) {
	connector := newFakeCloudConnector(endpoint.ConnectorTypeNGTS)
	connector.providers["p1"] = &domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS, Status: domain.CloudProviderStatusNotValidated}
	meta := &ProviderConfig{VCertClient: connector}
	r := resourceVenafiCloudProviderValidation()

	for id, want := range map[string]string{"p1": "is NOT_VALIDATED", "p2": "does not exist"} {
		d := r.TestResourceData()
		d.SetId(id)
		if _, err := r.Importer.StateContext(context.Background(), d, meta); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("expected an error containing %q for %s, got %v", want, id, err)
		}
	}

	connector.providers["p1"].Status = domain.CloudProviderStatusValidated
	d := r.TestResourceData()
	d.SetId("p1")
	if _, err := r.Importer.StateContext(context.Background(), d, meta); err != nil {
		t.Fatalf("unexpected error importing a validated provider: %s", err)
	}
}
