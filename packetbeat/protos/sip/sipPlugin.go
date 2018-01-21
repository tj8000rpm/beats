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

func (sip *sipPlugin) init(results protos.Reporter, config *sipConfig) error {
    sip.setFromConfig(config)
    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        sip.fragmentBufferTimeout,              // タイムアウト時間の設定
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
    sip.ports                 = config.Ports
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
// 受信バッファに入ったメッセージがタイムアウトした時の処理
func (sip *sipPlugin) expireBuffer(t *sipBuffer) {
    debugf("%s %s", "bufferTimeout.Error()", t.tuple.String())
    msg:=t.message
    switch msg.getMessageStatus(){
    case SIP_STATUS_HEADER_RECEIVING:
        msg.notes = append(msg.notes,common.NetString(fmt.Sprintf("Buffer timeout: Could not reveive all messages.")))
    case SIP_STATUS_BODY_RECEIVING:
        msg.notes = append(msg.notes,common.NetString(fmt.Sprintf("Buffer timeout: Could not reveive all content length.")))
    case SIP_STATUS_REJECTED: 
        return
    }
    sip.publishMessage(msg)
    bufferTimeout.Add(1)
}

func (sip *sipPlugin) ConnectionTimeout() time.Duration {
    return sip.fragmentBufferTimeout
}

// publishMessageはsipMessageをjsonとしてプッシュするように整形する
func (sip *sipPlugin) publishMessage(msg *sipMessage) {
    if sip.results == nil {
        return
    }

    debugf("Publishing SIP Message. %s", msg.String())

    timestamp := msg.ts
    fields := common.MapStr{}
    fields["sip.unixtimenano"] = timestamp.UnixNano()
    fields["type"] = "sip"
    fields["sip.transport"] = msg.transport.String()
    fields["sip.raw"] = string(msg.raw)
    fields["sip.src"] = fmt.Sprintf("%s:%d",msg.tuple.SrcIP,msg.tuple.SrcPort)
    fields["sip.dst"] = fmt.Sprintf("%s:%d",msg.tuple.DstIP,msg.tuple.DstPort)

    if msg.isRequest {
        fields["sip.method"     ] = fmt.Sprintf("%s",msg.method)
        fields["sip.request-uri"] = fmt.Sprintf("%s",msg.requestUri)
    }else{
        fields["sip.status-code"  ] = int(msg.statusCode)
        fields["sip.status-phrase"] = fmt.Sprintf("%s",msg.statusPhrase)
    }

    fields["sip.from"   ] = fmt.Sprintf("%s",msg.from)
    fields["sip.to"     ] = fmt.Sprintf("%s",msg.to)
    fields["sip.cseq"   ] = fmt.Sprintf("%s",msg.cseq)
    fields["sip.call-id"] = fmt.Sprintf("%s",msg.callid)

    sipHeaders := common.MapStr{}
    fields["sip.headers"] = sipHeaders

    if msg.headers != nil{
        for header,lines := range *(msg.headers){
            sipHeaders[header] = lines
        }
    }

    sipBody := common.MapStr{}
    fields["sip.body"] = sipBody

    if msg.body !=nil{
        for content,keyval := range (msg.body){
            contetMap := common.MapStr{}
            sipBody[content] = contetMap
            for key,val_lines := range *keyval{
                contetMap[key] = val_lines
            }
        }
    }

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

// createSIPMessage a byte array into a SIP struct. If an error occurs
// then the returned sip pointer will be nil. This method recovers from panics
// and is concurrency-safe.
func (sip *sipPlugin) createSIPMessage(transp transport, rawData []byte) (msg *sipMessage, err error) {
    // Recover from any panics that occur while parsing a packet.
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()

    // create and initialized pakcet raw message and transport type.
    msg = &sipMessage{}
    msg.transport=transp
    msg.raw = rawData

    // offset values are initialized to -1
    msg.hdr_start    =-1
    msg.hdr_len      =-1
    msg.bdy_start    =-1
    msg.contentlength=-1

    return msg, nil
}

func (sip *sipPlugin) newBuffer(ts time.Time, tuple sipTuple, cmd common.CmdlineTuple,msg *sipMessage) *sipBuffer {
    buffer := &sipBuffer{
        transport: tuple.transport,
        ts:        ts,
        tuple:     tuple,
        message:   msg,
    }
    return buffer
}

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
        // In case previous mesage not find in the buffer
        debugf("New sip message(not in buffer): %s",sipTuple)

        // create new SIP Message
        sipMsg, err = sip.createSIPMessage(transportUDP, pkt.Payload)

        if err != nil{
            // ignore this message
            debugf("error %s\n",err)
            return
        }

        sipMsg.ts   =pkt.Ts
        sipMsg.tuple=pkt.Tuple
        sipMsg.cmdlineTuple=procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple)
    }else{
        // In case previouse message find in the buffer
        sipMsg=buffer.message
        sipMsg.raw=append(sipMsg.raw,pkt.Payload...) // append to the previous message
        // parse again
    }

    // parse sip headers.
    // if the message was fragmented, the message buffered in below switch/case statement.
    parseHeaderErr:=sipMsg.parseSIPHeader()
    if parseHeaderErr != nil{
        debugf("error %s\n",parseHeaderErr)
        return
    }

    switch sipMsg.getMessageStatus(){
    // In case the message was fragmented at header or body,
    // buffering the message.
    case SIP_STATUS_HEADER_RECEIVING, SIP_STATUS_BODY_RECEIVING:
        debugf("fragmented packet")
        if buffer == nil{
            buffer = sip.newBuffer(sipMsg.ts, sipTuple, *sipMsg.cmdlineTuple, sipMsg)
        }
        sip.addBuffer(sipTuple.hashable(),buffer)
        return

    // In case the message received completely, publishing the message.
    case SIP_STATUS_RECEIVED:
        err := sipMsg.parseSIPBody()
        if err != nil{
            sipMsg.notes = append(sipMsg.notes,common.NetString(fmt.Sprintf("%s",err)))
        }
        sip.publishMessage(sipMsg)
    }
}

