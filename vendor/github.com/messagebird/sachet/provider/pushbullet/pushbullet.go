package pushbullet

import (
	"fmt"
	"strings"

	"github.com/xconstruct/go-pushbullet"

	"github.com/messagebird/sachet"
)

const (
	deviceTargetType  = "device"
	channelTargetType = "channel"
)

// Config is the configuration struct for the Pushbullet provider.
type Config struct {
	AccessToken string `yaml:"access_token"`
}

var _ (sachet.Provider) = (*Pushbullet)(nil)

// Pushbullet contains the necessary values for the Pushbullet provider.
type Pushbullet struct {
	Config
}

// NewPushbullet creates and returns a new Pushbullet struct.
func NewPushbullet(config Config) *Pushbullet {
	return &Pushbullet{config}
}

// Send pushes a note to devices registered in configuration.
func (c *Pushbullet) Send(message sachet.Message) error {
	for _, recipient := range message.To {
		// create pushbullet client.
		pb := pushbullet.New(c.AccessToken)

		// parse recipient.
		targetTypeName := strings.SplitN(recipient, ":", 2)
		if len(targetTypeName) != 2 {
			return fmt.Errorf("cannot parse recipient %s: expecting targetType:targetName", recipient)
		}
		targetType := targetTypeName[0]
		targetName := targetTypeName[1]

		switch targetType {
		case deviceTargetType:
			// retrieve device
			dev, err := pb.Device(targetName)
			if err != nil {
				return err
			}

			// push note
			err = pb.PushNote(dev.Iden, message.From, message.Text)
			if err != nil {
				return err
			}
		case channelTargetType:
			// retrieve subscription
			sub, err := pb.Subscription(targetName)
			if err != nil {
				return err
			}

			// push note
			err = sub.PushNote(message.From, message.Text)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unrecognised target type: %s", targetType)
		}
	}

	return nil
}
