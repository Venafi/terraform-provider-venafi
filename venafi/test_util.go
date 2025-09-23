//nolint:unused // False positive, as actually all of these variables and functions are used; it's just that they are used in other files
package venafi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"io"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	emptyPolicy                               = "/test_files/empty_policy.json"
	policySpecVaas                            = "/test_files/policy_specification_vaas.json"
	policySpecTpp                             = "/test_files/policy_specification_tpp.json"
	policyReadSpecTpp                         = "/test_files/policy_specification_tpp_management.json"
	validDays                                 = 30
	orgRecommendedSettingVaaSRestricted2      = "Venafi Inc."
	orgUnitsRecommendedSettingVaaSRestricted2 = "Customer Support"
	localityRecommendedSettingVaaSRestricted2 = "Salt Lake"
	stateRecommendedSettingVaaSRestricted2    = "Utah"
	countryRecommendedSettingVaaSRestricted2  = "US"
)

var (
	rsa2048 = `algorithm = "RSA"
               rsa_bits = "2048"`

	ecdsa521 = `algorithm = "ECDSA"
                ecdsa_curve = "P521"`
)

func RandAppName() string {
	return fmt.Sprintf("terraform-provider-%d-%sAppOpenSource", time.Now().Unix(), randRunes(4))
}

func RandCitName() string {
	return fmt.Sprintf("t%d-%sCitOpenSource", time.Now().Unix(), randRunes(4))
}

func RandTppPolicyName() string {
	return fmt.Sprintf("terraform-provider-%d-%sPolicyOpenSource", time.Now().Unix(), randRunes(4))
}

func randRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GetRootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func IsArrayStringEqual(expectedValues, values []string) bool {

	if len(expectedValues) != len(values) {
		return false
	}

	for i, currentValue := range expectedValues {

		if currentValue != values[i] {

			return false

		}

	}

	return true
}

func GetAbsoluteFIlePath(filePath string) string {
	rootDir := GetRootDir()
	absolutePath := rootDir + filePath
	return absolutePath
}

func RandTppSshCertName() string {
	return fmt.Sprintf("terraform-provider-%d-%sSSH-cert", time.Now().Unix(), randRunes(4))
}

func checkStandardCert(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Testing certificate with cn", data.cn)
	certUntyped := s.RootModule().Outputs["certificate"].Value
	cert, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", cert)
	if !strings.HasPrefix(cert, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	keyUntyped := s.RootModule().Outputs["private_key"].Value
	privateKey, ok := keyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"private_key\" is not a string")
	}

	err := checkStandardCertInfo(t, data, cert, privateKey)
	if err != nil {
		return err
	}
	return nil
}

func checkStandardCertForRecommendedSettings(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Testing certificate with cn", data.cn)
	certUntyped := s.RootModule().Outputs["certificate"].Value
	cert, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", cert)
	if !strings.HasPrefix(cert, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	keyUntyped := s.RootModule().Outputs["private_key"].Value
	privateKey, ok := keyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"private_key\" is not a string")
	}

	err := checkStandardCertInfo(t, data, cert, privateKey)
	if err != nil {
		return err
	}

	//checking subject info
	block, _ := pem.Decode([]byte(cert))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing cert: %s", err)
	}

	org := data.org
	if org == "" {
		org = orgRecommendedSettingVaaSRestricted2
	}
	if expected, got := []string{org}, certificate.Subject.Organization; !sameStringSlice(got, expected) {
		return fmt.Errorf("incorrect Organization: expected %v, certificate %v", expected, got)
	}

	orgUnit1 := data.orgUnit1
	orgUnit2 := data.orgUnit2
	if orgUnit1 == "" && orgUnit2 == "" {
		orgUnit1 = orgUnitsRecommendedSettingVaaSRestricted2
	}
	var orgUnits []string
	if orgUnit1 != "" {
		orgUnits = append(orgUnits, orgUnit1)
	}
	if orgUnit2 != "" {
		orgUnits = append(orgUnits, orgUnit2)
	}
	if expected, got := orgUnits, certificate.Subject.OrganizationalUnit; !sameStringSlice(got, expected) {
		return fmt.Errorf("incorrect Organizational Units: expected %v, certificate %v", expected, got)
	}

	country := data.country
	if country == "" {
		country = countryRecommendedSettingVaaSRestricted2
	}
	if expected, got := []string{country}, certificate.Subject.Country; !sameStringSlice(got, expected) {
		return fmt.Errorf("incorrect Country: expected %v, certificate %v", expected, got)
	}

	state := data.state
	if state == "" {
		state = stateRecommendedSettingVaaSRestricted2
	}
	if expected, got := []string{state}, certificate.Subject.Province; !sameStringSlice(got, expected) {
		return fmt.Errorf("incorrect State: expected %v, certificate %v", expected, got)
	}

	locality := data.locality
	if locality == "" {
		locality = localityRecommendedSettingVaaSRestricted2
	}
	if expected, got := []string{locality}, certificate.Subject.Locality; !sameStringSlice(got, expected) {
		return fmt.Errorf("incorrect Locality: expected %v, certificate %v", expected, got)
	}

	return nil
}

func checkStandardCertNew(resourceName string, t *testing.T, data *testData) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		t.Log("Testing certificate with cn", data.cn)
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}
		cert := rs.Primary.Attributes["certificate"]

		t.Logf("Testing certificate PEM:\n %s", cert)
		if !strings.HasPrefix(cert, "-----BEGIN CERTIFICATE----") {
			return fmt.Errorf("key is missing cert PEM preamble")
		}
		privateKey := rs.Primary.Attributes["private_key_pem"]
		err := checkStandardCertInfo(t, data, cert, privateKey)
		if err != nil {
			return err
		}
		return nil
	}
}

func checkStandardCertInfo(t *testing.T, data *testData, certificate string, privateKey string) error {
	block, _ := pem.Decode([]byte(certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing cert: %s", err)
	}
	if expected, got := data.cn, cert.Subject.CommonName; got != expected {
		return fmt.Errorf("incorrect subject common name: expected %v, certificate %v", expected, got)
	}
	if len(data.dns_ns) > 0 {
		if expected, got := []string{data.cn, data.dns_ns}, cert.DNSNames; !sameStringSlice(got, expected) {
			return fmt.Errorf("incorrect DNSNames: expected %v, certificate %v", expected, got)
		}
	}

	data.serial = cert.SerialNumber.String()
	data.timeCheck = time.Now().String()

	t.Logf("Testing private key PEM:\n %s", privateKey)
	privateKeyString, err := util.DecryptPkcs8PrivateKey(privateKey, data.private_key_password)
	if err != nil {
		return fmt.Errorf("error trying to decrypt key: %s", err)
	}
	privKeyPEMbytes := []byte(privateKeyString)

	_, err = tls.X509KeyPair([]byte(certificate), privKeyPEMbytes)
	if err != nil {
		return fmt.Errorf("error comparing certificate and key: %s", err)
	}
	return nil
}

func checkCertValidDays(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Testing certificate with cn", data.cn)
	certUntyped := s.RootModule().Outputs["certificate"].Value
	certStr, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", certStr)
	if !strings.HasPrefix(certStr, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	block, _ := pem.Decode([]byte(certStr))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing cert: %s", err)
	}

	certValidUntil := cert.NotAfter.Format("2006-01-02")

	//need to convert local date on utc, since the certificate' NotAfter value we got on previous step, is on utc
	//so for comparing them we need to have both dates on utc.
	loc, _ := time.LoadLocation("UTC")
	utcNow := time.Now().In(loc)
	expectedValidDate := utcNow.AddDate(0, 0, validDays).Format("2006-01-02")

	if expectedValidDate != certValidUntil {
		return fmt.Errorf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
	}

	return nil
}

func checkCertSans(t *testing.T, data *testData, s *terraform.State) error {
	t.Log("Getting expiration_window from terraform state", data.cn)
	sanUriUntyped := s.RootModule().Outputs["san_uri"].Value
	err := validateStringListFromSchemaAttribute(sanUriUntyped, "san_uri")
	if err != nil {
		return err
	}

	sanIpUntyped := s.RootModule().Outputs["san_ip"].Value
	err = validateStringListFromSchemaAttribute(sanIpUntyped, "san_ip")
	if err != nil {
		return err
	}
	return nil
}

func getCertTppImportConfig(name string) *testData {
	data := testData{}
	domain := "venafi.example.com"
	data.cn = name + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"
	return &data
}

func getCustomFields(variableName string) string {
	formattedData := ""

	data := os.Getenv(variableName)
	entries := strings.Split(data, ",")
	for _, value := range entries {
		formattedData = formattedData + value + ",\n"
	}
	return formattedData
}

func getCertTppImportConfigWithCustomFields() *testData {
	data := testData{}
	domain := "venafi.example.com"
	data.cn = "import.custom_fields" + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.private_key_password = "FooB4rNew4$x"
	cfEnvVarName := "TPP_CUSTOM_FIELDS"
	data.custom_fields = getCustomFields(cfEnvVarName)
	return &data
}

func getCertVaasImportConfig() *testData {
	data := testData{}
	domain := "venafi.example.com"
	data.cn = "new.import.vaas" + "." + domain
	data.key_algo = rsa2048
	data.private_key_password = "123xxx"
	return &data
}

func checkStandardImportCert(t *testing.T, data *testData, states []*terraform.InstanceState) error {
	st := states[0]
	attributes := st.Attributes
	err := checkImportCert(t, data, attributes)
	if err != nil {
		return err
	}
	return nil

}

func checkImportTppCertWithCustomFields(t *testing.T, data *testData, states []*terraform.InstanceState) error {
	st := states[0]
	attributes := st.Attributes
	err := checkImportCert(t, data, attributes)
	if err != nil {
		return err
	}
	err = checkImportedCustomFields(t, data.custom_fields, attributes)
	if err != nil {
		return err
	}
	return nil
}

func checkImportWithObjectName(t *testing.T, data *testData, states []*terraform.InstanceState) error {
	st := states[0]
	attributes := st.Attributes
	err := checkImportCert(t, data, attributes)
	if err != nil {
		return err
	}
	nickname := attributes[venafiCertificateAttrNickname]
	if nickname != data.nickname {
		return fmt.Errorf("nickname in imported resource differs from the input")
	}
	return nil
}

func checkImportCert(t *testing.T, data *testData, attr map[string]string) error {
	cert := attr["certificate"]
	privateKey := attr["private_key_pem"]
	err := checkStandardCertInfo(t, data, cert, privateKey)
	if err != nil {
		return err
	}
	return nil
}

func checkImportedCustomFields(t *testing.T, dataCf string, attr map[string]string) error {
	t.Logf("Comparing imported custom fields with the ones in the test file")

	// creating map from string
	var customFieldsMap map[string]string
	// cleaning data string from special characters

	dataCf = strings.TrimSuffix(dataCf, ",\n")
	dataCf = strings.ReplaceAll(dataCf, "\n", "")
	dataCf = strings.ReplaceAll(dataCf, "\"", "")
	customFieldsRow := strings.Split(dataCf, ",")
	customFieldsRow = deleteEmptyString(customFieldsRow)
	customFieldsMap = make(map[string]string)
	for _, pair := range customFieldsRow {
		z := strings.Split(pair, "=")
		customFieldsMap[z[0]] = z[1]
	}
	for key, value := range customFieldsMap {
		keyAttr := fmt.Sprintf("custom_fields.%s", key)
		if attr[keyAttr] != value {
			return fmt.Errorf("\"%s\" custom field is different, expected: %s, got: %s", key, value, attr[keyAttr])
		}
	}
	return nil
}

func createCertificate(t *testing.T, cfg *vcert.Config, data *testData, serviceGenerated bool) string {
	t.Log("Creating certificate for testing")

	var auth = &endpoint.Authentication{}
	switch cfg.ConnectorType {
	case endpoint.ConnectorTypeTPP:
		cfg.BaseUrl = os.Getenv("TPP_URL")
		cfg.Zone = os.Getenv("TPP_ZONE")
		if data.zone != "" {
			cfg.Zone = data.zone
		}
		trustBundlePath := os.Getenv("TRUST_BUNDLE")
		trustBundleBytes, err := os.ReadFile(trustBundlePath)
		if err != nil {
			t.Fatalf("Error opening trust bundle file: %s", err.Error())
		}
		cfg.ConnectionTrust = string(trustBundleBytes)
		auth.AccessToken = os.Getenv("TPP_ACCESS_TOKEN")
	case endpoint.ConnectorTypeCloud:
		cfg.BaseUrl = os.Getenv("CLOUD_URL")
		cfg.Zone = os.Getenv("CLOUD_ZONE")
		cfg.Zone = removingFirstDoubleBackslash(cfg.Zone)
		auth.APIKey = os.Getenv("CLOUD_APIKEY")
	default:
		t.Fatalf("Unsupported connector type: %s", cfg.ConnectorType)
	}

	cfg.Credentials = auth
	client, err := vcert.NewClient(cfg)
	if err != nil {
		t.Fatalf("Error building VCert client %s", err.Error())
	}
	// here stops
	zoneConfig, err := client.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("error reading zone configuration: %s", err)
	}
	req := &certificate.Request{}
	if data.nickname != "" && cfg.ConnectorType == endpoint.ConnectorTypeTPP {
		t.Logf("Certificate: %s", data.nickname)
	} else {
		//at least cn mus be set for TPP
		t.Logf("Certificate: %s", data.cn)
	}
	if data.cn != "" {
		req.Subject.CommonName = data.cn
	}
	if data.private_key_password != "" {
		req.KeyPassword = data.private_key_password
	}
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	if data.dns_ns != "" {
		req.DNSNames = strings.Split(data.dns_ns, ",")
	}
	if data.dns_ip != "" {
		req.IPAddresses = stringArrayToIParray(strings.Split(data.dns_ip, ","))
	}
	// this is the name that will show up on CyberArk Certificate Manager, SaaS UI
	if data.nickname != "" {
		req.FriendlyName = data.nickname
	}
	if data.valid_days != 0 {
		days := time.Duration(data.valid_days)
		d := 24 * days
		req.ValidityDuration = &d
	}
	req.IssuerHint = util.IssuerHintMicrosoft
	req.CsrOrigin = certificate.LocalGeneratedCSR

	if data.custom_fields != "" {
		data.custom_fields = strings.ReplaceAll(data.custom_fields, "\n", "")
		customFields := strings.Split(data.custom_fields, ",")
		customFields = deleteEmptyString(customFields)
		for _, cf := range customFields {
			cf = strings.TrimSuffix(cf, ",\n")
			cf = strings.ReplaceAll(cf, "\n", "")
			cf = strings.ReplaceAll(cf, "\"", "")
			k, v, err := parseCustomField(cf)
			if err != nil {
				t.Fatal(err)
			}
			list := strings.Split(v, "|")
			for _, value := range list {
				value = strings.TrimSpace(value)
				req.CustomFields = append(req.CustomFields, certificate.CustomField{Name: k, Value: value})
			}
		}
	}

	if serviceGenerated {
		req.CsrOrigin = certificate.ServiceGeneratedCSR
	}
	err = client.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("error generating request: %s", err)
	}
	t.Log("Requesting Certificate")
	pickupID, err := client.RequestCertificate(req)
	if err != nil {
		t.Fatalf("error requesting certificate: %s", err)
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast

	var pcc *certificate.PEMCollection
	startTime := time.Now()
	for {
		if serviceGenerated {
			req.Timeout = 180 * time.Second
			req.KeyPassword = data.private_key_password
			if cfg.ConnectorType == endpoint.ConnectorTypeTPP {
				req.FetchPrivateKey = true
			}
		}
		t.Log("Retrieving certificate")
		pcc, err = client.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("error retrieving certificate: %s", err)
	}
	t.Log("Verifying certificate")
	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("error parsing certificate: %s", err)
	}

	if data.valid_days != 0 {
		certValidUntil := cert.NotAfter.Format("2006-01-02")
		loc, _ := time.LoadLocation("UTC")
		utcNow := time.Now().In(loc)
		expectedValidDate := utcNow.AddDate(0, 0, data.valid_days).Format("2006-01-02")
		// ensure certificate is created with our provided time
		if expectedValidDate != certValidUntil {
			t.Fatalf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
		}
	}
	t.Log("Certificate creation successful")
	return pickupID
}

func removingFirstDoubleBackslash(s string) string {
	firstInd := strings.Index(s, "\\")
	newString := s[0:firstInd] + s[firstInd+1:]
	return newString
}

func parseCustomField(s string) (key, value string, err error) {
	sl := strings.Split(s, "=")
	if len(sl) < 2 {
		err = fmt.Errorf("custom field should have format key=value")
		return
	}
	key = strings.TrimSpace(sl[0])
	value = strings.TrimSpace(strings.Join(sl[1:], "="))
	return
}

func deleteEmptyString(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func checkCreatePolicy(t *testing.T, data *testData, s *terraform.State, validateAttr bool) error {
	t.Log("Validate Creating empty policy", data.zone)

	pstUntyped := s.RootModule().Outputs["policy_specification"].Value

	ps, ok := pstUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"policy_specification\" is not a string")
	}

	bytes := []byte(ps)

	var policySpecification policy.PolicySpecification
	err := json.Unmarshal(bytes, &policySpecification)
	if err != nil {
		return fmt.Errorf("policy specification is nil")
	}

	if !validateAttr {
		return nil
	}

	//get policy on directory.
	file, err := os.Open(data.filePath)
	if err != nil {
		return err
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var filePolicySpecification policy.PolicySpecification
	err = json.Unmarshal(fileBytes, &filePolicySpecification)
	if err != nil {
		return err
	}

	equal := IsArrayStringEqual(filePolicySpecification.Policy.Domains, policySpecification.Policy.Domains)
	if !equal {
		return fmt.Errorf("domains are different, expected %+q but get %+q", filePolicySpecification.Policy.Domains, policySpecification.Policy.Domains)
	}

	//compare some attributes.

	if *(filePolicySpecification.Policy.MaxValidDays) != *(policySpecification.Policy.MaxValidDays) {
		return fmt.Errorf("max valid period is different, expected %s but get %s", strconv.Itoa(*(filePolicySpecification.Policy.MaxValidDays)), strconv.Itoa(*(policySpecification.Policy.MaxValidDays)))
	}

	equal = IsArrayStringEqual(filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)

	if !equal {
		return fmt.Errorf("key types are different, expected %+q but get %+q", filePolicySpecification.Policy.KeyPair.KeyTypes, policySpecification.Policy.KeyPair.KeyTypes)
	}

	equal = IsArrayStringEqual(filePolicySpecification.Policy.Subject.Countries, policySpecification.Policy.Subject.Countries)

	if !equal {
		return fmt.Errorf("countries are different, expected %+q but get %+q", filePolicySpecification.Policy.Subject.Countries, policySpecification.Policy.Subject.Countries)
	}

	if *(filePolicySpecification.Default.Subject.Locality) != *(policySpecification.Default.Subject.Locality) {
		return fmt.Errorf("default locality is different, expected %s but get %s", *(filePolicySpecification.Default.Subject.Locality), *(policySpecification.Default.Subject.Locality))
	}

	return nil
}
