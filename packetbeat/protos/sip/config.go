package sip

import (
    "github.com/elastic/beats/packetbeat/config"
)

type sipConfig struct {
    config.ProtocolCommon       `config:",inline"`
    ParseDetail           bool  `config:"parse_detail"`
}

var (
    defaultConfig = sipConfig{
        ProtocolCommon: config.ProtocolCommon{},
		ParseDetail: false,
    }
)

