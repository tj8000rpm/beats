package sip

import (
    "fmt"
    "time"

    "github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
    "github.com/elastic/beats/libbeat/logp"

    "github.com/elastic/beats/packetbeat/procs"
    "github.com/elastic/beats/packetbeat/protos"
)

/**
 ******************************************************************
 * sipPlugin
 ******************************************************************
 **/
type sipPlugin struct {
    // Configuration data.
    ports              []int

    // SIPのアクティブなトランザクションをキャッシュする。
    // Cache of active SIP transactions. The map key is the HashableSipTuple
    // associated with the request.
    fragmentBuffer        *common.Cache
    fragmentBufferTimeout time.Duration

    results protos.Reporter // Channel where results are pushed.
}

// Transactionとしてタイムアウトさせる方法とかがここにありそう。
func (sip *sipPlugin) init(results protos.Reporter, config *sipConfig) error {
    sip.setFromConfig(config)
    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        sip.fragmentBufferTimeout,                 // タイムアウト時間の設定
        protos.DefaultTransactionHashSize,      // ハッシュサイズの設定
        func(k common.Key, v common.Value) {    // remove時のCallbackFunction
            buffer, ok := v.(*sipBuffer)
            if !ok {
                logp.Err("Expired value is not a *sipBuffer.")
                return
            }
            sip.expireBuffer(buffer)
        })
    sip.fragmentBuffer.StartJanitor(sip.fragmentBufferTimeout)

    sip.results = results

    return nil
}

// configの値からSIPとして扱うポートとかいろいろ設定できるっぽい
func (sip *sipPlugin) setFromConfig(config *sipConfig) error {
    sip.ports = config.Ports
    sip.fragmentBufferTimeout = config.BufferTimeout
    return nil
}

func (sip *sipPlugin) GetPorts() []int {
    return sip.ports
}

func (sip *sipPlugin) addBuffer(k hashableSIPTuple,buffer *sipBuffer) {
    sip.fragmentBuffer.Put(k, buffer)
}

// getBuffer returns the transaction associated with the given
// HashableSipTuple. The lookup key should be the HashableDnsTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (sip *sipPlugin) getBuffer(k hashableSIPTuple) *sipBuffer {
    v := sip.fragmentBuffer.Get(k)
    if v != nil {
        return v.(*sipBuffer)
    }
    return nil
}

// deleteTransaction deletes an entry from the transaction map and returns
// the deleted element. If the key does not exist then nil is returned.
func (sip *sipPlugin) deleteBuffer(k hashableSIPTuple) *sipBuffer {
    v := sip.fragmentBuffer.Delete(k)
    if v != nil {
        return v.(*sipBuffer)
    }
    return nil
}
// トランザクションがタイムアウトした時の処理
func (sip *sipPlugin) expireBuffer(t *sipBuffer) {
    t.notes = append(t.notes, "noResponse.Error()")
    debugf("%s %s", "noResponse.Error()", t.tuple.String())
    sip.publishBuffer(t)
    unmatchedRequests.Add(1)
}

func (sip *sipPlugin) ConnectionTimeout() time.Duration {
    return sip.fragmentBufferTimeout
}

// publishTransactionはひとつのトランザクションを
// Elasticsearchに書き出すためのデータを作る過程??
func (sip *sipPlugin) publishBuffer(t *sipBuffer) {
    if sip.results == nil {
        return
    }

    debugf("Publishing transaction. %s", t.tuple.String())

    timestamp := t.ts
    fields := common.MapStr{}
    fields["type"] = "sip"
    fields["transport"] = t.transport.String()
    fields["uac"] = &t.uac
    fields["uas"] = &t.uas
// コンパイル通すためにいったんコメントアウト
//    fields["status"] = common.ERROR_STATUS
//    if len(t.notes) == 1 {
//        fields["notes"] = t.notes[0]
//    } else if len(t.notes) > 1 {
//        fields["notes"] = strings.Join(t.notes, " ")
//    }
//
    sipEvent := common.MapStr{}
    fields["sip"] = sipEvent

// コンパイル通すためにいったんコメントアウト
//    if t.request != nil && t.response != nil {
//        fields["bytes_in"] = t.request.length
//        fields["bytes_out"] = t.response.length
//        fields["responsetime"] = int32(t.response.ts.Sub(t.ts).Nanoseconds() / 1e6)
//        fields["method"] = sipOpCodeToString(t.request.data.Opcode)
//        if len(t.request.data.Question) > 0 {
//            fields["query"] = sipQuestionToString(t.request.data.Question[0])
//            fields["resource"] = t.request.data.Question[0].Name
//        }
//        addSIPToMapStr(sipEvent, t.response.data, sip.includeAuthorities,
//            sip.includeAdditionals)
//
//        if t.response.data.Rcode == 0 {
//            fields["status"] = common.OK_STATUS
//        }
//
//        if sip.sendRequest {
//            fields["request"] = sipToString(t.request.data)
//        }
//        if sip.sendResponse {
//            fields["response"] = sipToString(t.response.data)
//        }
//    } else if t.request != nil {
//        fields["bytes_in"] = t.request.length
//        fields["method"] = sipOpCodeToString(t.request.data.Opcode)
//        if len(t.request.data.Question) > 0 {
//            fields["query"] = sipQuestionToString(t.request.data.Question[0])
//            fields["resource"] = t.request.data.Question[0].Name
//        }
//        addSIPToMapStr(sipEvent, t.request.data, sip.includeAuthorities,
//            sip.includeAdditionals)
//
//        if sip.sendRequest {
//            fields["request"] = sipToString(t.request.data)
//        }
//    } else if t.response != nil {
//        fields["bytes_out"] = t.response.length
//        fields["method"] = sipOpCodeToString(t.response.data.Opcode)
//        if len(t.response.data.Question) > 0 {
//            fields["query"] = sipQuestionToString(t.response.data.Question[0])
//            fields["resource"] = t.response.data.Question[0].Name
//        }
//        addSIPToMapStr(sipEvent, t.response.data, sip.includeAuthorities,
//            sip.includeAdditionals)
//        if sip.sendResponse {
//            fields["response"] = sipToString(t.response.data)
//        }
//    }

    sip.results(beat.Event{
        Timestamp: timestamp,
        Fields:    fields,
    })
}

func (sip *sipPlugin) sipTupleFromIPPort(t *common.IPPortTuple, trans transport) sipTuple {

    tuple := sipTuple{
        ipLength:  t.IPLength,
        SrcIP:     t.SrcIP,
        DstIP:     t.DstIP,
        SrcPort:   t.SrcPort,
        DstPort:   t.DstPort,
        transport: trans,
    }
    tuple.computeHashebles()

    return tuple
}

// decodeSIPData decodes a byte array into a SIP struct. If an error occurs
// then the returned sip pointer will be nil. This method recovers from panics
// and is concurrency-safe.
func (sip *sipPlugin) createSIPMessage(transp transport, rawData []byte) (msg *sipMessage, err error) {
    // SipMessageを作成、rawDataを保持
    msg = &sipMessage{}
    msg.raw = rawData

    msg.hdr_start    =-1
    msg.hdr_len      =-1
    msg.bdy_start    =-1
    msg.contentlength=-1

//    var offset int
//    if transp == transportTCP {
//        offset = decodeOffset
//    }


    // Recover from any panics that occur while parsing a packet.
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()
    return msg, nil
}

// udpパケットで呼ばれた際のパース
func (sip *sipPlugin) ParseUDP(pkt *protos.Packet) {

    defer logp.Recover("Sip ParseUdp")
    packetSize := len(pkt.Payload)

    debugf("Parsing packet addressed with %s of length %d.",
        pkt.Tuple.String(), packetSize)
    sipTuple := sip.sipTupleFromIPPort(&pkt.Tuple, transportUDP)
    var buffer *sipBuffer
    buffer = sip.deleteBuffer(sipTuple.hashable())

    var sipMsg *sipMessage
    var err error

    if buffer == nil {
        // 新規もの
        fmt.Printf(": %s\n",sipTuple)

        sipMsg, err = sip.createSIPMessage(transportUDP, pkt.Payload)
        sipMsg.ts   =pkt.Ts
        sipMsg.tuple=pkt.Tuple
        sipMsg.cmdlineTuple=procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple)

        parseHeaderErr:=sipMsg.parseSIPHeader()
        if parseHeaderErr != nil{
            fmt.Printf("error %s\n",parseHeaderErr)
            return
        }
    }else{
        // 続き物
        sipMsg=buffer.message
        sipMsg.raw=append(sipMsg.raw,pkt.Payload...)
        sipMsg.parseSIPHeader()
    }
    
    // SIPメッセージがヘッダの途中でフラグメントされていた場合
    if sipMsg.hdr_len <= 0 {
        fmt.Printf("Header fragment")
        if buffer == nil{
            buffer = newBuffer(sipMsg.ts, sipTuple, *sipMsg.cmdlineTuple, sipMsg)
        }
        sip.addBuffer(sipTuple.hashable(),buffer)
        return

    // SIPメッセージがボディの途中でフラグメントされていた場合
    } else if sipMsg.contentlength == -1{
        fmt.Printf("Body fragment")

        if buffer == nil{
            buffer = newBuffer(sipMsg.ts, sipTuple, *sipMsg.cmdlineTuple, sipMsg)
        }
        sip.addBuffer(sipTuple.hashable(),buffer)
        return

    } else {
    }

    // なんの問題もなく、ボディがある場合はボディをパースする
    if sipMsg.contentlength > 0 {
        sipMsg.parseSIPBody()
    }

    fmt.Printf("%s\n",sipMsg)
    _ = err

}

