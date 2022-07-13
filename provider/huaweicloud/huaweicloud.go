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

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func wsseHeader(appKey,appSecret string)string {
	const WsseHeaderFormat = `UsernameToken Username="%s",PasswordDigest="%s",Nonce="%s",Created="%s"`

	cTime := time.Now().Format("2006-01-02T15:04:05Z")
	nonce := strings.ReplaceAll(uuid.NewV4().String(),"-","")

	hash := sha256.New()
	hash.Write([]byte(nonce + cTime + appSecret))
	passwordDigest := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	return fmt.Sprintf(WsseHeaderFormat, appKey, passwordDigest, nonce, cTime)
}

func substituteInvalidChars(str string) string {
	const InvalidCharRegex = `[^\p{Han}\w\d_\-\/=:\[\]\* ]+`
	reg, _ := regexp.Compile(InvalidCharRegex)
	result := str

	if !strings.ContainsAny(result, ".<>") {
		return result
	}

	specialCharSub := map[string]string{
		// IP separator
		"." : "-",
		// Huawei SMS not support > & <
		">=": "ge",
		"<=": "le",
		">" : "gt",
		"<" : "lt",
	}
	// substitute special chars
	for oldChar, newChar := range specialCharSub {
		result = strings.ReplaceAll(result, oldChar, newChar)
	}

	// substitute invalid characters
	result = reg.ReplaceAllString(result, "@")
	return result
}

func abbreviateString(str string) string {
	result := str
	const templateVarMaxLength = 20
	// cut down string
	if len(result) > templateVarMaxLength {
		result = result[:templateVarMaxLength-3] + "***"
	} else {
		result = result
	}
	return result
}

func safeMessage(message sachet.Message) string {
	// transformation: alerts -> go template result(txt) -> HuaweiCloud SMS template vars
	paramsArray := strings.SplitN(strings.TrimSpace(message.Text), " ", 6)

	for index, param := range paramsArray {
		param = substituteInvalidChars(param)
		param = abbreviateString(param)
		paramsArray[index] = param
	}

	// for Huawei SMS template: exchange template var position
	paramsArray[3], paramsArray[4], paramsArray[5] = paramsArray[5], paramsArray[3], paramsArray[4]
	// todo: change SMS template
	jsonArray, _ := json.Marshal(paramsArray[0:5])
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

	templateParams := safeMessage(message)

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
	header.Add("X-WSSE", wsseHeader(appKey, appSecret))

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
