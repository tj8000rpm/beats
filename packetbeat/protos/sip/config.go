package sip

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type sipConfig struct {
	config.ProtocolCommon `config:",inline"`
	IncludeAuthorities    bool `config:"include_authorities"`
	IncludeAdditionals    bool `config:"include_additionals"`
}

var (
	defaultConfig = sipConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
