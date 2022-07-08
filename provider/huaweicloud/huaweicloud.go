package huaweicloud

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"regexp"
	"strings"

	"encoding/json"
	"fmt"
	"github.com/messagebird/sachet"
	uuid "github.com/satori/go.uuid"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	Address    string `yaml:"api_address"`
	Key        string `yaml:"app_key"`
	Secret     string `yaml:"app_secret"`
	Sender     string `yaml:"sender"`
	TemplateID string `yaml:"template_id"`
	Sign       string `yaml:"sign"`
}

var _ (sachet.Provider) = (*HuaweiCloud)(nil)

type HuaweiCloud struct {
	Config
	httpClient *http.Client
}

func NewHuaweiCloud(config Config) *HuaweiCloud {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	return &HuaweiCloud{
		config,
		client,
	}
}

func WsseHeader(appKey,appSecret string)string {
	const WsseHeaderFormat = `UsernameToken Username="%s",PasswordDigest="%s",Nonce="%s",Created="%s"`

	cTime := time.Now().Format("2006-01-02T15:04:05Z")
	nonce := strings.ReplaceAll(uuid.NewV4().String(),"-","")

	hash := sha256.New()
	hash.Write([]byte(nonce + cTime + appSecret))
	passwordDigest := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	return fmt.Sprintf(WsseHeaderFormat, appKey, passwordDigest, nonce, cTime)
}

func SafeMessage(message sachet.Message) string {
	const templateVarMaxLength = 20
	const InvalidCharRegex = `[^\w\d_\-\/=:\[\]\* ]+`
	reg, _ := regexp.Compile(InvalidCharRegex)

	// transformation: alerts -> go template result(txt) -> HuaweiCloud SMS template vars
	paramsArray := strings.SplitN(strings.TrimSpace(message.Text), " ", 3)
	for index, param := range paramsArray {

		// substitute IP separator
		param = strings.ReplaceAll(param, ".", "-")
		// substitute invalid characters
		param = reg.ReplaceAllString(param, "@")
		// cut down string
		if len(param) > templateVarMaxLength {
			paramsArray[index] = param[:templateVarMaxLength-3] + "***"
		} else {
			paramsArray[index] = param
		}
	}
	jsonArray, _ := json.Marshal(paramsArray)
	return string(jsonArray)
}

// Send sends SMS to user registered in configuration.
func (c *HuaweiCloud) Send(message sachet.Message) error {
	const AuthHeaderValue = `WSSE realm="SDP",profile="UsernameToken",type="Appkey"`

	apiAddress := c.Config.Address
	appKey     := c.Config.Key
	appSecret  := c.Config.Secret
	sender     := c.Config.Sender
	templateId := c.Config.TemplateID
	signature  := c.Config.Sign

	receivers := strings.Join(message.To,",")
	statusCallBack := ""

	templateParams := SafeMessage(message)

	params := url.Values{}
	params.Add("from", sender)
	params.Add("to", receivers)
	params.Add("templateId", templateId)
	if templateParams != "" { params.Add("templateParas", templateParams) }
	if statusCallBack != "" { params.Add("statusCallback", statusCallBack) }
	if signature      != "" { params.Add("signature", signature) }

	body := params.Encode()
	header := http.Header{}
	header.Add("Content-Type", "application/x-www-form-urlencoded")
	header.Add("Authorization", AuthHeaderValue)
	header.Add("X-WSSE", WsseHeader(appKey, appSecret))

	req, err := http.NewRequest("POST",apiAddress, bytes.NewBuffer([]byte(body)))
	req.Header = header

	resp, err := c.httpClient.Do(req)
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := map[string]string{}
	_ = json.Unmarshal(b, &result)

	if result["description"] == "Success" {
		fmt.Println("OK")
	}
	fmt.Println(result)
	fmt.Errorf("code:%s message:%s", result["code"], result["description"])
	return err
}
