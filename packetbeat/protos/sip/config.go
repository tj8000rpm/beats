package sip

import (
    "time"
	"github.com/elastic/beats/packetbeat/config"
)

type sipConfig struct {
	config.ProtocolCommon       `config:",inline"`
    BufferTimeout time.Duration `config:"buffer_timeout"`
}

var (
	defaultConfig = sipConfig{
		ProtocolCommon: config.ProtocolCommon{
//			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
        BufferTimeout: 5 * time.Second,
	}
)
