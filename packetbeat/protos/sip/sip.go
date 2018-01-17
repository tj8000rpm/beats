// based on dns plugin
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

// TODOなんやこれ
// きっと何か失敗したときに返すもの・・・NewIntの処理は不明のため調べる
var (
    unmatchedRequests  = monitoring.NewInt(nil, "sip.unmatched_requests")
    unmatchedResponses = monitoring.NewInt(nil, "sip.unmatched_responses")
)

// const maxDNSTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1 // bytes?
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

// SIPなのでダイアログで取るのはメモリやリアルタイム性から微妙と判断
// SIPのメッセージは1つ1つをそのまま書き出す方向で実装
// UDPのフラグメントだけ気にして実装
type sipBuffer struct {
    ts           time.Time // Time when the request was received.
    tuple        sipTuple  // Key used to track this transaction in the transactionsMap.
    uac          common.Endpoint
    uas          common.Endpoint
    transport    transport
    notes        []string
    message  *sipMessage
}

/**
 * どの構造体にも属さないメソッド ------------------------------------
 **/

// protosに対してSIPと関数Newを紐付ける
func init() {
    protos.Register("sip", New)
}

// NewはProtosから呼び出されるっぽい。
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

// %sで呼び出す時の暗黙関数名 -> String()
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

