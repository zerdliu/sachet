package cm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/messagebird/sachet"
)

// Config is the configuration struct for CM provider.
type Config struct {
	ProductToken string `yaml:"producttoken"`
}

var _ (sachet.Provider) = (*CM)(nil)

// CM contains the necessary values for the CM provider.
type CM struct {
	Config
}

var cmHTTPClient = &http.Client{Timeout: time.Second * 20}

// NewCM creates and returns a new CM struct.
func NewCM(config Config) *CM {
	return &CM{config}
}

type CMRecipient struct {
	Number string `json:"number"`
}

type CMMessage struct {
	From string        `json:"from"`
	To   []CMRecipient `json:"to"`
	Body struct {
		Content string `json:"content"`
	} `json:"body"`
}

type CMPayload struct {
	Messages struct {
		Authentication struct {
			ProductToken string `json:"producttoken"`
		} `json:"authentication"`
		MSG []CMMessage `json:"msg"`
	} `json:"messages"`
}

// Send sends SMS to n number of people using Bulk SMS API.
func (c *CM) Send(message sachet.Message) error {
	smsURL := "https://gw.cmtelecom.com/v1.0/message"

	payload := CMPayload{}
	payload.Messages.Authentication.ProductToken = c.Config.ProductToken
	payload.Messages.MSG = append(payload.Messages.MSG, CMMessage{})

	payload.Messages.MSG[0].From = message.From
	payload.Messages.MSG[0].Body.Content = message.Text

	for _, recipient := range message.To {
		payload.Messages.MSG[0].To = append(
			payload.Messages.MSG[0].To,
			CMRecipient{
				Number: recipient,
			},
		)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", smsURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Sachet")

	response, err := cmHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	var body []byte
	_, err = response.Body.Read(body)
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusOK && err == nil {
		return nil
	}

	return fmt.Errorf("Failed sending sms. Reason: %s, statusCode: %d", string(body), response.StatusCode)
}
