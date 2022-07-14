package huaweicloud

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"encoding/json"
	"fmt"
	"github.com/messagebird/sachet"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

type Config struct {
	Address    string `yaml:"api_address"`
	Key        string `yaml:"app_key"`
	Secret     string `yaml:"app_secret"`
	Sender     string `yaml:"sender"`
	TemplateID string `yaml:"template_id"`
	Sign       string `yaml:"sign"`
}

type Response struct {
	Code string `json:"code"`
	Description string `json:"description"`
	Result []ResponseDetail `json:"result"`
}

type ResponseDetail struct {
	OriginTo string `json:"originTo"`
	CreateTime string `json:"createTime"`
	From string `json:"from"`
	SmsMsgId string `json:"smsMsgId"`
	Status string `json:"status"`

}

var _ (sachet.Provider) = (*HuaweiCloud)(nil)

type HuaweiCloud struct {
	Config
	httpClient *http.Client
	zerolog.Logger
}

func NewHuaweiCloud(config Config) *HuaweiCloud {
	programName := filepath.Base(os.Args[0])

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	logFile, err := os.OpenFile(programName + ".log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatal().Msgf("Can't open file: %v", err)
	}
	//defer logFile.Close()

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	logger := log.Output(logFile).With().
		Str("service", "webhook-sms").
		Str("provider", "huaweicloud-sms").
		Caller().
		Logger()

	return &HuaweiCloud{
		config,
		client,
		logger,
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
	//jsonArray, _ := json.Marshal(paramsArray)
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

	c.Logger.Info().
		Str("action", "receive").
		Str("receivers", strings.Join(message.To,",")).
		Str("from", message.From).
		Str("type", message.Type).
		Msg(message.Text)

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
	if err != nil {
		c.Logger.Err(err)
	}

	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		c.Logger.Err(err).Msg("")
	}

	detail, err := json.Marshal(response.Result)
	if err != nil {
		c.Logger.Err(err).Msg("")
	}

	c.Logger.Info().
		Str("action", "send").
		Str("receivers", strings.Join(message.To,",")).
		Int("http_code", resp.StatusCode).
		Str("error_code", response.Code).
		Str("error_description", response.Description).
		Msg(string(detail))

	return err
}
