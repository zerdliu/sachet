package telegram

import (
	"strconv"

	tgbotapi "gopkg.in/telegram-bot-api.v4"

	"github.com/messagebird/sachet"
)

type Config struct {
	Token                 string `yaml:"token"`
	ParseMode             string `yaml:"parse_mode"`
	DisableWebPagePreview bool   `yaml:"disable_web_page_preview"`
}

var _ (sachet.Provider) = (*Telegram)(nil)

type Telegram struct {
	bot    *tgbotapi.BotAPI
	config *Config
}

func NewTelegram(config Config) (*Telegram, error) {
	bot, err := tgbotapi.NewBotAPI(config.Token)
	if err != nil {
		return nil, err
	}

	return &Telegram{
		bot:    bot,
		config: &config,
	}, nil
}

func (tg *Telegram) Send(message sachet.Message) error {
	for _, sChatID := range message.To {
		chatID, err := strconv.ParseInt(sChatID, 10, 64)
		if err != nil {
			return err
		}

		msg := tgbotapi.NewMessage(chatID, message.Text)
		msg.ParseMode = tg.config.ParseMode
		msg.DisableWebPagePreview = tg.config.DisableWebPagePreview

		_, err = tg.bot.Send(msg)
		if err != nil {
			return err
		}
	}
	return nil
}
