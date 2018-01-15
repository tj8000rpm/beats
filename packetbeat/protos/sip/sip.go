// based on dns plugin
package sip

import (
//    "bytes"
    "fmt"
    "net"
//    "sort"
    "strconv"
    "strings"
    "time"
    //"crypto/sha256"
    //"encoding/binary"
    //"reflect"

    "github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
    "github.com/elastic/beats/libbeat/logp"
    "github.com/elastic/beats/libbeat/monitoring"

    "github.com/elastic/beats/packetbeat/procs"
    "github.com/elastic/beats/packetbeat/protos"
)

var (
    debugf = logp.MakeDebug("sip")
)


// Only EDNS packets should have their size beyond this value
const maxSIPPacketSize = (1 << 9) // 512 (bytes)


// TODOなんやこれ
// そのDNSメッセージががQueryなのかRespoinseなのかを表すためのモノっぽい。
// SIPにしたら request = false, response = true か？
// Constants used to associate the SIP Req. Res. flag with a meaningful value.
//dns/ Constants used to associate the DNS QR flag with a meaningful value.
const (
    request  = false
    response = true
)

// TODOなんやこれ
// きっと何か失敗したときに返すもの・・・NewIntの処理は不明のため調べる
var (
    unmatchedRequests  = monitoring.NewInt(nil, "sip.unmatched_requests")
    unmatchedResponses = monitoring.NewInt(nil, "sip.unmatched_responses")
)

// iotaは連番の生成
// transportTCP = 0
// transportUDP = 1
// 2回目以降は省略したら事前の定義が引き継がれる
const (
    transportTCP = iota
    transportUDP
)


// const maxDNSTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1 // bytes?
const maxHashableSipTupleRawSize = 16 + // ip addr (src) 128bit(ip v6)
                                   16 + // ip addr (dst) 128bit(ip v6)
                                    2 + // port number (src) 16bit
                                    2 + // port number (dst) 16bit
                                    1   // transport 8bit 

type hashableSIPTuple [maxHashableSipTupleRawSize]byte


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



func newBuffer(ts time.Time, tuple sipTuple, cmd common.CmdlineTuple,msg *sipMessage) *sipBuffer {
    buffer := &sipBuffer{
        transport: tuple.transport,
        ts:        ts,
        tuple:     tuple,
        message:   msg,
    }
    return buffer
}

// Adds the SIP message data to the supplied MapStr.
func addSIPToMapStr(m common.MapStr, sip []byte, authority bool, additional bool) {
    m["id"] = sip[32:39]
}


// sipToString converts a SIP message to a string.
func sipToString(sip []byte) string {
    var a []string

    return strings.Join(a, "; ")
}

func getLastElementStrArray(array []common.NetString) common.NetString{
    return array[len(array)-1]
}

func rightIpLargeThanLeftIp(leftip net.IP,rightip net.IP) bool {

    for i:=0; i<len(leftip);i++{
        left_ed :=leftip[i]
        right_ed:=rightip[i]

        if(left_ed<right_ed){
            return true
        }else if left_ed==right_ed {
            continue
        }else{
            return false
        }
    }
    return false
}

/**
 ******************************************************************
 * transport
 *******************************************************************
 **/

// きっとトランスポートプロトコルのTCPだとかUDPだとかを保持する変数
// transport=0 tcp, transport=1, udpみたいでつ。
// Transport protocol.
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

/**
 ******************************************************************
 * sipMessage
 *******************************************************************
 **/

// SipMessage contains a single SIP message.
type sipMessage struct {
    ts           time.Time          // Time when the message was received.
    tuple        common.IPPortTuple // Source and destination addresses of packet.
    cmdlineTuple *common.CmdlineTuple

    // SIP FirstLines
    isRequest    bool
    method       common.NetString
    requestUri   common.NetString
    statusCode   uint16
    statusPhrase common.NetString

    // SIP Headers
    from         common.NetString
    to           common.NetString
    cseq         common.NetString
    callid       common.NetString
    headers      *map[string][]common.NetString
    contentlen   int

    // SIP Bodies
    body      map[string]*map[string][]common.NetString

    // Raw Data
    raw          []byte

    // Offsets
    hdr_start    int
    hdr_end      int
    bdy_start    int
    bdy_end      int

}

func (msg sipMessage) String() string {
    outputs:=""
    if msg.isRequest{
        outputs+="Request: ("
        outputs+=string(msg.method)
        outputs+=", "
        outputs+=string(msg.requestUri)
        outputs+=")\n"
    }else{
        outputs+="Response: ("
        outputs+=fmt.Sprintf("%03d",msg.statusCode)
        outputs+=", "
        outputs+=string(msg.statusPhrase)
        outputs+=")\n"
    }
    outputs+=" From   : "+string(msg.from)+"\n"
    outputs+=" To     : "+string(msg.to)+"\n"
    outputs+=" CSeq   : "+string(msg.cseq)+"\n"
    outputs+=" Call-ID: "+string(msg.callid)+"\n"
    outputs+=" Headers: \n"
    for header,array := range *(msg.headers){
        for idx,line:= range array{
            outputs+=fmt.Sprintf(" - %20s[%3d] : %s\n",header,idx,line)
        }
    }
    outputs+=" body: \n"
    for body,maps_p := range msg.body{
        outputs+=fmt.Sprintf(" - %s\n",body)
        if(body == "application/sdp"){
            for key,lines:= range *maps_p{
                for idx,line:= range lines{
                    outputs+=fmt.Sprintf("  - %5s[%3d] : %s\n",key,idx,line)
                }
            }
        }
    }
    return outputs
}
func (msg *sipMessage) parseSIPHeader(){
    msg.hdr_start =-1
    msg.hdr_end   =-1
    msg.bdy_start =-1
    msg.bdy_end   =-1
    msg.contentlen=-1


    // SIPのヘッダとボディの区切りとそれまでのCRLFで改行が入っている箇所を探す
    cutPosS := []int{} // SIPメッセージの先頭、またはCRLFの直後のバイト位置
    cutPosE := []int{} // CRLFの直前のバイト位置

    byte_len := len(msg.raw)
    hdr_start:=-1       // SIPメッセージの始まり位置を-1で初期化
    hdr_end  :=byte_len // SIPのボディの終了位置(CRLFCRLF)位置を受け取ったbyte arrayの長さで初期化
    bdy_start:=byte_len // SIPのボディの終了位置(CRLFCRLF)位置を受け取ったbyte arrayの長さで初期化
    bdy_end  :=byte_len 

    for i,ch := range msg.raw {
        //冒頭の\r\nを無視していく
        if hdr_start == -1 {
            if ch == byte('\n') || ch == byte('\r') {
                continue
            }else{
                cutPosS = append(cutPosS,i)
                hdr_start=i
            }
        }

        //CRLFの全部の場所を取得
        if i+1<byte_len &&
                msg.raw[i+0] == byte('\r') && msg.raw[i+1] == byte('\n'){
            cutPosE = append(cutPosE,i)
            cutPosS = append(cutPosS,i+2)
        }
        //ヘッダ終了位置の確認
        if i+3<byte_len &&
                msg.raw[i+0] == byte('\r') && msg.raw[i+1] == byte('\n') &&
                msg.raw[i+2] == byte('\r') && msg.raw[i+3] == byte('\n'){
            hdr_end=i
            bdy_start=i+4
            break
        }
    }
    
    // hdr_startの値を記載
    msg.hdr_start=hdr_start

    // TODO:ヘッダの終了位置がわからなかった時とかの処理
    // fragmented packetが入ってきた場合はこっちに来るのでその処理を書かないと・・・
    if hdr_start < 0 || byte_len <= hdr_end{
        return
    }
    
    msg.hdr_end  =hdr_end
    msg.bdy_start=bdy_start

    // 正常系処理
    // SIP
    headers, first_lines:=msg.parseSIPHeaderToMap(cutPosS,cutPosE)

    // mandatory header fields check
    to_array         , existTo          := (*headers)["to"          ]
    from_array       , existFrom        := (*headers)["from"        ]
    cseq_array       , existCSeq        := (*headers)["cseq"        ]
    callid_array     , existCallId      := (*headers)["call-id"     ]
    maxfrowards_array, existMaxForwards := (*headers)["max-forwards"]
    via_array        , existVia         := (*headers)["via"         ]

    // TODO: 処理をきちんとかく
    // 必須ヘッダ不足
    if !(existTo && existFrom && existCSeq && existCallId && existMaxForwards && existVia){
    }

    msg.to    =getLastElementStrArray(to_array)
    msg.from  =getLastElementStrArray(from_array)
    msg.cseq  =getLastElementStrArray(cseq_array)
    msg.callid=getLastElementStrArray(callid_array)

    msg.headers=headers

    _=maxfrowards_array
    _=via_array

    // リクエストかレスポンスかを判定
    msg.isRequest = strings.Contains(first_lines[2],"SIP/2.0")
    if msg.isRequest {
        msg.method    =common.NetString(first_lines[0])
        msg.requestUri=common.NetString(first_lines[1])
    }else if strings.Contains(first_lines[0],"SIP/2.0") { // Response
        parsedStatusCode,err := strconv.ParseInt(first_lines[1],10,16)
        _ = err
        
        // TODO:パース失敗時のエラーハンドリングを追加
        msg.statusCode  =uint16(parsedStatusCode)
        msg.statusPhrase=common.NetString(first_lines[2])
    }else{
        // TODO:Malformed Packets
        // 何かしらのエラーハンドリングが必要
    }

    // Content-Lenghtは0でいったん初期化
    msg.contentlen = 0
    contenttype_array  , existContentType   := (*headers)["content-type"]
    contentlength_array, existContentLength := (*headers)["content-length"]
    _ = contenttype_array

    // TODO: 処理をきちんとかく
    // ボディがない（または不正な）パターン
    if !existContentType || !existContentLength{
        return 
    }

    contentlength,err := strconv.ParseInt(string(getLastElementStrArray(contentlength_array)),10,64)
    // TODO:パース失敗時のエラーハンドリングを追加
    _ =err

    msg.contentlen=int(contentlength)
    bdy_end=bdy_start+int(contentlength)

    if bdy_end <= byte_len {
        // TODO:
        // fragmented packetの場合、未受信部分があるのでバッファリングの処理に入る・・・かな？
        // とりあえず現状は取れる分だけとっとく。
        msg.bdy_end=bdy_end
    }

}

func (msg *sipMessage) parseSIPHeaderToMap(cutPosS []int,cutPosE []int) (*map[string][]common.NetString,[]string) {
    first_lines:=[]string{}
    headers:=&map[string][]common.NetString{}

    var lastheader string
    for i:=0;i<len(cutPosE);i++ {
        s:=cutPosS[i]
        e:=cutPosE[i]

        if i==0 { // Requst-line or Status-Lineが入るはず。
            first_lines=strings.SplitN(string(msg.raw[s:e])," ",3)
        }else{
            // 途中で改行された場合の処理(先頭がスペース、またはタブ)
            // Call-Id: hogehoge--adslfaaiii
            //  higehige@hogehoge.com
            // みたいなケース
            if msg.raw[s] == byte(' ') || msg.raw[s] == byte('\t'){
                if lastheader!=""{
                    lastelement:=string(getLastElementStrArray((*headers)[lastheader]))
                    // TrimSpaceは" "と"\t"の両方削除してくれる
                    lastelement+=strings.TrimSpace(string(msg.raw[s:e]))
                }else{
                    // 当該行を無視する
                }
                continue
            }
            // 先頭がスペースまたはタブ出ない時はヘッダパラメータのはず
            header_kv:=strings.SplitN(string(msg.raw[s:e]),":",2)
            key:=strings.ToLower(strings.TrimSpace(header_kv[0]))
            val:=strings.TrimSpace(header_kv[1])
            _,ok := (*headers)[key]
            if !ok{
                (*headers)[key]=[]common.NetString{}
            }

            (*headers)[key]=append((*headers)[key],common.NetString(val))
            lastheader=key
        }
    }
    return headers, first_lines
}

func (msg *sipMessage) parseSIPBody(){

    contenttype_array  , _   := (*msg.headers)["content-type"]
    msg.body=map[string]*map[string][]common.NetString{}

    // bodyの種類により動作を変更する
    lower_case_content_type:=strings.ToLower(string(getLastElementStrArray(contenttype_array)))
    switch(lower_case_content_type){
        case "application/sdp":
            body,err:=msg.parseBody_SDP(msg.raw[msg.bdy_start:msg.bdy_end])
            _ = err

            msg.body[lower_case_content_type]=body

        default:
            fmt.Printf("unspported content-type.\n")

    }

    // TODO: 処理をきちんとかく
    return 
}

func (msg sipMessage) parseBody_SDP(rawData []byte) (body *map[string][]common.NetString, err error){
    body=&map[string][]common.NetString{}
    sdp_lines:=strings.Split(string(rawData),"\r\n")
    for i:=0;i<len(sdp_lines);i++{

        key_val:=strings.SplitN(sdp_lines[i],"=",2)

        if len(key_val)!=2{
            continue
        }

        key:=strings.TrimSpace(key_val[0])
        val:=strings.TrimSpace(key_val[1])

        _, existkey:=(*body)[key]
        if !existkey {
           (*body)[key]=[]common.NetString{} 
        }
        (*body)[key]=append((*body)[key],common.NetString(val))
    }

    return body, nil
}

func (msg sipMessage) addRawData(rawData []byte) {
    for _,bdata:= range rawData{
        msg.raw=append(msg.raw,bdata)
    }
}


/**
 ******************************************************************
 * sipTuple
 *******************************************************************
 **/

 // SIPTuple contains source IP/port, destination IP/port, transport protocol,
// and SIP Hashed Call-ID.
// Memo:
//  Call-IDの長さは決まらない気がするのでハッシュ化して長さを一定にする・・
type sipTuple struct {
    ipLength                 int
    smallIP, largeIP         net.IP
    smallIpPort, largeIpPort uint16
    transport                transport

    raw    hashableSIPTuple // smallIP:smallIpPort:larageIP:largeIpPort:transport
}

//めっちゃハードコードやん・・
// とりあえずDNSとおんなじ方法で
func (t *sipTuple) computeHashebles() {
    copy(t.raw[0:16], t.smallIP)
    copy(t.raw[16:18], []byte{byte(t.smallIpPort >> 8), byte(t.smallIpPort)})
    copy(t.raw[18:34], t.largeIP)
    copy(t.raw[34:36], []byte{byte(t.largeIpPort >> 8), byte(t.largeIpPort)})
    t.raw[36] = byte(t.transport)
}

func (t sipTuple) String() string {
    return fmt.Sprintf("sipTuple small[%s:%d] large[%s:%d] transport[%s]",
        t.smallIP.String(),
        t.smallIpPort,
        t.largeIP.String(),
        t.largeIpPort,
        t.transport)
}

// Hashable returns a hashable value that uniquely identifies
// the SIP tuple.
func (t *sipTuple) hashable() hashableSIPTuple {
    return t.raw
}

/**
 ******************************************************************
 * sipPlugin
 ******************************************************************
 **/
type sipPlugin struct {
    // Configuration data.
    ports              []int
    sendRequest        bool
    sendResponse       bool
    includeAuthorities bool
    includeAdditionals bool

    // SIPのアクティブなトランザクションをキャッシュする。
    // Cache of active SIP transactions. The map key is the HashableSipTuple
    // associated with the request.
    fragmentBuffer       *common.Cache
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
                logp.Err("Expired value is not a *SipTransaction.")
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
    sip.sendRequest = config.SendRequest
    sip.sendResponse = config.SendResponse
    sip.includeAuthorities = config.IncludeAuthorities
    sip.includeAdditionals = config.IncludeAdditionals
    sip.fragmentBufferTimeout = config.TransactionTimeout
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

    var smallIP     net.IP
    var largeIP     net.IP
    var smallIpPort uint16
    var largeIpPort uint16

    Dst_lt_Src:=true

    // SIPアドレスの大小で判断させる
    if rightIpLargeThanLeftIp(t.SrcIP,t.DstIP) || t.SrcIP.Equal(t.DstIP) && t.SrcPort < t.DstPort{
        Dst_lt_Src=false
    }

    // Dst < Srcの時の処理
    if Dst_lt_Src{
        smallIP     = t.DstIP
        smallIpPort = t.DstPort
        largeIP     = t.SrcIP
        largeIpPort = t.SrcPort
    // Dst >= Srcの時の処理
    }else{
        smallIP     = t.SrcIP
        smallIpPort = t.SrcPort
        largeIP     = t.DstIP
        largeIpPort = t.DstPort
    }
    
    tuple := sipTuple{
        ipLength:      t.IPLength,
        smallIP:       smallIP,
        largeIP:       largeIP,
        smallIpPort:   smallIpPort,
        largeIpPort:   largeIpPort,
        transport:     trans,
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

    msg.hdr_start =-1
    msg.hdr_end   =-1
    msg.bdy_start =-1
    msg.bdy_end   =-1
    msg.contentlen=-1

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

        sipMsg.parseSIPHeader()
    }else{
        // 続き物
        fmt.Printf("バッファあるで!\n")
        sipMsg=buffer.message
        sipMsg.raw=append(sipMsg.raw,pkt.Payload...)
        //fmt.Printf("%s\n",string(sipMsg.raw))
        sipMsg.parseSIPHeader()
        //return
    }

    // SIPメッセージがヘッダの途中でフラグメントされていた場合
    if sipMsg.hdr_end == -1{
        fmt.Printf("Header fragment")
        if buffer == nil{
            buffer = newBuffer(sipMsg.ts, sipTuple, *sipMsg.cmdlineTuple, sipMsg)
        }
        sip.addBuffer(sipTuple.hashable(),buffer)
        return

    // SIPメッセージがボディの途中でフラグメントされていた場合
    } else if sipMsg.bdy_end == -1{
        fmt.Printf("Body fragment")

        if buffer == nil{
            buffer = newBuffer(sipMsg.ts, sipTuple, *sipMsg.cmdlineTuple, sipMsg)
        }
        sip.addBuffer(sipTuple.hashable(),buffer)
        return

    } else {
    }

    if sipMsg.bdy_start < sipMsg.bdy_end {
        sipMsg.parseSIPBody()
    }

    fmt.Printf("%s\n",sipMsg)
    _ = err

}
//    sipPkt, err := decodeSIPData(transportUDP, pkt.Payload)
//    if err != nil {
//        // This means that malformed requests or responses are being sent or
//        // that someone is attempting to the DNS port for non-DNS traffic. Both
//        // are issues that a monitoring system should report.
//        debugf("%s", err.Error())
//        return
//    }
//
//    sipTuple := sipTupleFromIPPort(&pkt.Tuple, transportUDP, sipPkt.Id)
//    dnsMsg := &dnsMessage{
//        ts:           pkt.Ts,
//        tuple:        pkt.Tuple,
//        cmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
//        data:         sipPkt,
//        length:       packetSize,
//    }
//
//    if sipMsg.data.Response {
//        sip.receivedSIPResponse(&sipTuple, sipMsg)
//    } else /* Query */ {
//        sip.receivedSIPRequest(&sipTuple, sipMsg)
//    }
//}
// 参考：MemchaceのParseUDP
// func (mc *memcache) ParseUDP(pkt *protos.Packet) {
//     defer logp.Recover("ParseMemcache(UDP) exception")
// 
//     buffer := streambuf.NewFixed(pkt.Payload)
//     header, err := parseUDPHeader(buffer)
//     if err != nil {
//         debug("parsing memcache udp header failed")
//         return
//     }
// 
//     debug("new udp datagram requestId=%v, seqNumber=%v, numDatagrams=%v",
//         header.requestID, header.seqNumber, header.numDatagrams)
// 
//     // find connection object based on ips and ports (forward->reverse connection)
//     connection, dir := mc.getUDPConnection(&pkt.Tuple)
//     debug("udp connection: %p", connection)
// 
//     // get udp transaction combining forward/reverse direction 'streams'
//     // for current requestId
//     trans := connection.udpTransactionForID(header.requestID)
//     debug("udp transaction (id=%v): %p", header.requestID, trans)
// 
//     // Clean old transaction. We do the cleaning after potentially adding a new
//     // transaction to the connection object, so connection object will not be
//     // cleaned accidentally (not bad, but let's rather reuse it)
//     expTrans := mc.udpExpTrans.steal()
//     for expTrans != nil {
//         tmp := expTrans.next
//         expTrans.connection.killTransaction(expTrans)
//         expTrans = tmp
//     }
// 
//     // get UDP transaction stream combining datagram packets in transaction
//     udpMsg := trans.udpMessageForDir(&header, dir)
//     if udpMsg.numDatagrams != header.numDatagrams {
//         logp.Warn("number of datagram mismatches in stream")
//         connection.killTransaction(trans)
//         return
//     }
// 
//     // try to combine datagrams into complete memcached message
//     payload := udpMsg.addDatagram(&header, buffer.Bytes())
//     done := false
//     if payload != nil {
//         // parse memcached message
//         msg, err := parseUDP(&mc.config, pkt.Ts, payload)
//         if err != nil {
//             logp.Warn("failed to parse memcached(UDP) message: %s", err)
//             connection.killTransaction(trans)
//             return
//         }
// 
//         // apply memcached to transaction
//         done, err = mc.onUDPMessage(trans, &pkt.Tuple, dir, msg)
//         if err != nil {
//             logp.Warn("error processing memcache message: %s", err)
//             connection.killTransaction(trans)
//             done = true
//         }
//     }
//     if !done {
//         trans.timer = time.AfterFunc(mc.udpConfig.transTimeout, func() {
//             debug("transaction timeout -> forward")
//             mc.onUDPTrans(trans)
//             mc.udpExpTrans.push(trans)
//         })
//     }
// }
