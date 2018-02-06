package sip

import (
    "time"

    "github.com/elastic/beats/libbeat/common"
    "github.com/elastic/beats/libbeat/logp"
    "github.com/elastic/beats/libbeat/monitoring"

    "github.com/elastic/beats/packetbeat/protos"
)

var (
    debugf = logp.MakeDebug("sip")
)

// Packetbeats monitoring metrics
var (
    bufferTimeout  = monitoring.NewInt(nil, "sip.buffer_timeouted")
    
    messageIgnored = monitoring.NewInt(nil, "sip.message_ignored")
)

const maxHashableSipTupleRawSize = 16 + // ip addr (src) 128bit(ip v6)
                                   16 + // ip addr (dst) 128bit(ip v6)
                                    2 + // port number (src) 16bit
                                    2 + // port number (dst) 16bit
                                    1   // transport 8bit 

type hashableSIPTuple [maxHashableSipTupleRawSize]byte

const  (
    transportTCP = 0
    transportUDP = 1
)

const (
    SIP_STATUS_RECEIVED         = 0
    SIP_STATUS_HEADER_RECEIVING = 1
    SIP_STATUS_BODY_RECEIVING   = 2
    SIP_STATUS_REJECTED         = 3
)

// SIPなのでダイアログで取るのはメモリやリアルタイム性から微妙と判断
// SIPのメッセージは1つ1つをそのまま書き出す方向で実装
// UDPのフラグメントだけ気にして実装
type sipBuffer struct {
    ts           time.Time // Time when the request was received.
    tuple        sipTuple  // Key used to track this transaction in the transactionsMap.
    uac          common.Endpoint
    uas          common.Endpoint
    transport    transport
    message      *sipMessage
}

/**
 * どの構造体にも属さないメソッド ------------------------------------
 **/

func init() {
    protos.Register("sip", New)
}

func New(
    testMode bool,
    results protos.Reporter,
    cfg *common.Config,
) (protos.Plugin, error) {
    p := &sipPlugin{}
    config := defaultConfig
    if !testMode {
        if err := cfg.Unpack(&config); err != nil {
            return nil, err
        }
    }

    if err := p.init(results, &config); err != nil {
        return nil, err
    }
    return p, nil
}

func getLastElementStrArray(array []common.NetString) common.NetString{
    return array[len(array)-1]
}

/**
 ******************************************************************
 * transport
 *******************************************************************
 **/

// Transport protocol.
// transport=0 tcp, transport=1, udp
type transport uint8

func (t transport) String() string {

    transportNames := []string{
        "tcp",
        "udp",
    }

    if int(t) >= len(transportNames) {
        return "impossible"
    }
    return transportNames[t]
}

