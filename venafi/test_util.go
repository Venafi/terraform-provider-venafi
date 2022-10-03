package venafi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	emptyPolicy       = "/test_files/empty_policy.json"
	policySpecVaas    = "/test_files/policy_specification_vaas.json"
	policySpecTpp     = "/test_files/policy_specification_tpp.json"
	policyReadSpecTpp = "/test_files/policy_specification_tpp_management.json"
	issuerHint        = "MICROSOFT"
	validDays         = 30
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
	certificate, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", certificate)
	if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	keyUntyped := s.RootModule().Outputs["private_key"].Value
	privateKey, ok := keyUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"private_key\" is not a string")
	}

	err := checkStandardCertInfo(t, data, certificate, privateKey)
	if err != nil {
		return err
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
		certificate := rs.Primary.Attributes["certificate"]

		t.Logf("Testing certificate PEM:\n %s", certificate)
		if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE----") {
			return fmt.Errorf("key is missing cert PEM preamble")
		}
		privateKey := rs.Primary.Attributes["private_key_pem"]
		err := checkStandardCertInfo(t, data, certificate, privateKey)
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
	} else {
		if expected, got := []string{data.cn}, cert.DNSNames; !sameStringSlice(got, expected) {
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
	certificate, ok := certUntyped.(string)
	if !ok {
		return fmt.Errorf("output for \"certificate\" is not a string")
	}

	t.Logf("Testing certificate PEM:\n %s", certificate)
	if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE----") {
		return fmt.Errorf("key is missing cert PEM preamble")
	}
	block, _ := pem.Decode([]byte(certificate))
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

func checkCertExpirationWindowChange(resourceName string, t *testing.T, data *testData) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		t.Log("Getting expiration_window from terraform state", data.cn)
		//gotExpirationWindow := s.RootModule().Outputs["expiration_window"].Value.(string)
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}
		gotExpirationWindow := rs.Primary.Attributes["expiration_window"]
		expirationWindow := strconv.Itoa(data.expiration_window)
		if gotExpirationWindow == expirationWindow {
			return fmt.Errorf(fmt.Sprintf("expiration window should have changed during enroll. current: %s got from zone: %s", expirationWindow, gotExpirationWindow))
		}
		return nil
	}
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
	objectName := attributes["object_name"]
	if objectName != data.object_name {
		return fmt.Errorf("object name in imported resource differs from the input")
	}
	return nil
}

func checkImportCert(t *testing.T, data *testData, attr map[string]string) error {
	certificate := attr["certificate"]
	privateKey := attr["private_key_pem"]
	err := checkStandardCertInfo(t, data, certificate, privateKey)
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

func createCertificate(t *testing.T, cfg *vcert.Config, data *testData, serviceGenerated bool) {
	t.Log("Creating certificate for testing")
	cfg.Zone = data.zone

	var auth = &endpoint.Authentication{}
	if cfg.ConnectorType == endpoint.ConnectorTypeTPP {
		cfg.BaseUrl = os.Getenv("TPP_URL")
		cfg.Zone = os.Getenv("TPP_ZONE")
		auth.AccessToken = os.Getenv("TPP_ACCESS_TOKEN")
	} else if cfg.ConnectorType == endpoint.ConnectorTypeCloud {
		cfg.BaseUrl = os.Getenv("CLOUD_URL")
		cfg.Zone = os.Getenv("CLOUD_ZONE")
		auth.APIKey = os.Getenv("CLOUD_APIKEY")
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
	if data.object_name != "" && cfg.ConnectorType == endpoint.ConnectorTypeTPP {
		t.Logf("Certificate: %s", data.object_name)
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
	// this is the name that will show up on VaaS UI
	if data.object_name != "" {
		req.FriendlyName = data.object_name
	}
	if data.valid_days != 0 {
		req.ValidityHours = data.valid_days * 24
	}
	req.IssuerHint = issuerHint
	req.CsrOrigin = certificate.LocalGeneratedCSR
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
}
