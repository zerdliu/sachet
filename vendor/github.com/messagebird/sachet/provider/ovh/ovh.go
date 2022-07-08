package ovh

import (
	"fmt"

	"github.com/ovh/go-ovh/ovh"

	"github.com/messagebird/sachet"
)

type Config struct {
	Endpoint          string `yaml:"endpoint"`
	ApplicationKey    string `yaml:"application_key"`
	ApplicationSecret string `yaml:"application_secret"`
	ConsumerKey       string `yaml:"consumer_key"`

	ServiceName       string `yaml:"service_name"`
	SenderForResponse string `yaml:"sender_for_response"`
	NoStopClause      bool   `yaml:"no_stop_clause"`
	Priority          string `yaml:"priority"`
}

var _ (sachet.Provider) = (*Ovh)(nil)

type Ovh struct {
	client *ovh.Client
	config *Config
}

func NewOvh(config Config) (*Ovh, error) {
	client, err := ovh.NewClient(
		config.Endpoint,
		config.ApplicationKey,
		config.ApplicationSecret,
		config.ConsumerKey,
	)
	if err != nil {
		return nil, err
	}
	return &Ovh{
		client: client,
		config: &config,
	}, nil
}

func (ovh *Ovh) Send(message sachet.Message) error {
	var err error = nil
	switch message.Type {
	case "", "text":
		type ovhSMS map[string]interface{}
		sms := make(ovhSMS)
		sms["message"] = message.Text
		sms["noStopClause"] = &ovh.config.NoStopClause
		sms["sender"] = message.From
		sms["senderForResponse"] = &ovh.config.SenderForResponse
		sms["receivers"] = message.To
		if ovh.config.Priority != "" {
			sms["priority"] = &ovh.config.Priority
		}
		serviceName := &ovh.config.ServiceName

		if err := ovh.client.Post("/sms/"+*serviceName+"/jobs", sms, nil); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown message type %s", message.Type)
	}
	return err
}
