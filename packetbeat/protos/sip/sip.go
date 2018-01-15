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

    "github.com/elastic/beats/packetbeat/protos"

)

var (
    debugf = logp.MakeDebug("sip")
)

// const maxDNSTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1 // bytes?
const maxHashableSipTupleRawSize = 16 + // ip addr (src) 128bit(ip v6)
                                   16 + // ip addr (dst) 128bit(ip v6)
                                    2 + // port number (src) 16bit
                                    2 + // port number (dst) 16bit
                                    4 + // id 32bit
                                    1   // transport 8bit 

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

// きっとトランスポートプロトコルのTCPだとかUDPだとかを保持する変数
// transport=0 tcp, transport=1, udpみたいでつ。
// Transport protocol.
type transport uint8

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

var transportNames = []string{
    "tcp",
    "udp",
}

// var=t transport
// t=0
// print(t.String())
// >> tcpみたいな。
func (t transport) String() string {
    if int(t) >= len(transportNames) {
        return "impossible"
    }
    return transportNames[t]
}

type hashableSIPTuple [maxHashableSipTupleRawSize]byte


// TODO
// 管理方法を考える
// TransactionよりもSIPの場合はDialogとしたほうがよいか？
// そもそもRequest-Responseを識別する必要もあるのか・・・？
// それともSIPのTransactionで管理したほうがよいか？
type sipTransaction struct {
    ts           time.Time // Time when the request was received.
    tuple        sipTuple  // Key used to track this transaction in the transactionsMap.
    responseTime int32     // Elapsed time in milliseconds between the request and response.
    src          common.Endpoint
    dst          common.Endpoint
    transport    transport
    notes        []string
    // んーsipだしどうやってデータをもつべきだろうか・・・？
    request  *sipMessage
    response *sipMessage
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


func sipTupleFromIPPort(t *common.IPPortTuple, trans transport, id uint16) sipTuple {
    tuple := sipTuple{
        ipLength:  t.IPLength,
        srcIP:     t.SrcIP,
        dstIP:     t.DstIP,
        srcPort:   t.SrcPort,
        dstPort:   t.DstPort,
        transport: trans,
        id:        id,
    }
    tuple.computeHashebles()

    return tuple
}

func newTransaction(ts time.Time, tuple sipTuple, cmd common.CmdlineTuple) *sipTransaction {
    trans := &sipTransaction{
        transport: tuple.transport,
        ts:        ts,
        tuple:     tuple,
    }
    trans.src = common.Endpoint{
        IP:   tuple.srcIP.String(),
        Port: tuple.srcPort,
        Proc: string(cmd.Src),
    }
    trans.dst = common.Endpoint{
        IP:   tuple.dstIP.String(),
        Port: tuple.dstPort,
        Proc: string(cmd.Dst),
    }
    return trans
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
    //headers:=map[string][]common.NetString{}
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
    ipLength         int
    srcIP, dstIP     net.IP
    srcPort, dstPort uint16
    transport        transport
    //hashed_callid    uint32??
    id             uint16 //idと一応しておくだれがIDふるのかわからんけど・・・ 

    raw    hashableSIPTuple // Src_ip:Src_port:Dst_ip:Dst_port:Transport:id ***Hashed_Call-Id
    revRaw hashableSIPTuple // Dst_ip:Dst_port:Src_ip:Src_port:Transport:id ***Hashed_Call-Id
}

func (t sipTuple) reverse() sipTuple {
    return sipTuple{
        ipLength:  t.ipLength,
        srcIP:     t.dstIP,
        dstIP:     t.srcIP,
        srcPort:   t.dstPort,
        dstPort:   t.srcPort,
        transport: t.transport,
        id:        t.id,
        raw:       t.revRaw,
        revRaw:    t.raw,
    }
}

//めっちゃハードコードやん・・
// とりあえずDNSのままで
func (t *sipTuple) computeHashebles() {
    copy(t.raw[0:16], t.srcIP)
    copy(t.raw[16:18], []byte{byte(t.srcPort >> 8), byte(t.srcPort)})
    copy(t.raw[18:34], t.dstIP)
    copy(t.raw[34:36], []byte{byte(t.dstPort >> 8), byte(t.dstPort)})
    copy(t.raw[36:38], []byte{byte(t.id >> 8), byte(t.id)})
    t.raw[39] = byte(t.transport)

    copy(t.revRaw[0:16], t.dstIP)
    copy(t.revRaw[16:18], []byte{byte(t.dstPort >> 8), byte(t.dstPort)})
    copy(t.revRaw[18:34], t.srcIP)
    copy(t.revRaw[34:36], []byte{byte(t.srcPort >> 8), byte(t.srcPort)})
    copy(t.revRaw[36:38], []byte{byte(t.id >> 8), byte(t.id)})
    t.revRaw[39] = byte(t.transport)
}

func (t *sipTuple) String() string {
    return fmt.Sprintf("sipTuple src[%s:%d] dst[%s:%d] transport[%s] id[%d]",
        t.srcIP.String(),
        t.srcPort,
        t.dstIP.String(),
        t.dstPort,
        t.transport,
        t.id)
}

// Hashable returns a hashable value that uniquely identifies
// the DNS tuple.
func (t *sipTuple) hashable() hashableSIPTuple {
    return t.raw
}

// Hashable returns a hashable value that uniquely identifies
// the DNS tuple after swapping the source and destination.
func (t *sipTuple) revHashable() hashableSIPTuple {
    return t.revRaw
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
    transactions       *common.Cache
    transactionTimeout time.Duration

    results protos.Reporter // Channel where results are pushed.
}
// Transactionとしてタイムアウトさせる方法とかがここにありそう。
func (sip *sipPlugin) init(results protos.Reporter, config *sipConfig) error {
    sip.setFromConfig(config)
    sip.transactions = common.NewCacheWithRemovalListener(
        sip.transactionTimeout,
        protos.DefaultTransactionHashSize,
        func(k common.Key, v common.Value) {
            trans, ok := v.(*sipTransaction)
            if !ok {
                logp.Err("Expired value is not a *SipTransaction.")
                return
            }
            sip.expireTransaction(trans)
        })
    sip.transactions.StartJanitor(sip.transactionTimeout)

    sip.results = results

    return nil
}
// 参考HTTPのinit
// // Init initializes the HTTP protocol analyser.
// func (http *httpPlugin) init(results protos.Reporter, config *httpConfig) error {
//     http.setFromConfig(config)
// 
//     isDebug = logp.IsDebug("http")
//     isDetailed = logp.IsDebug("httpdetailed")
//     http.results = results
//     return nil
// }


// configの値からSIPとして扱うポートとかいろいろ設定できるっぽい
func (sip *sipPlugin) setFromConfig(config *sipConfig) error {
    sip.ports = config.Ports
    sip.sendRequest = config.SendRequest
    sip.sendResponse = config.SendResponse
    sip.includeAuthorities = config.IncludeAuthorities
    sip.includeAdditionals = config.IncludeAdditionals
    sip.transactionTimeout = config.TransactionTimeout
    return nil
}

// getTransaction returns the transaction associated with the given
// HashableSipTuple. The lookup key should be the HashableDnsTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (sip *sipPlugin) getTransaction(k hashableSIPTuple) *sipTransaction {
    v := sip.transactions.Get(k)
    if v != nil {
        return v.(*sipTransaction)
    }
    return nil
}

// deleteTransaction deletes an entry from the transaction map and returns
// the deleted element. If the key does not exist then nil is returned.
func (sip *sipPlugin) deleteTransaction(k hashableSIPTuple) *sipTransaction {
    v := sip.transactions.Delete(k)
    if v != nil {
        return v.(*sipTransaction)
    }
    return nil
}

func (sip *sipPlugin) GetPorts() []int {
    return sip.ports
}

func (sip *sipPlugin) ConnectionTimeout() time.Duration {
    return sip.transactionTimeout
}

func (sip *sipPlugin) receivedSIPRequest(tuple *sipTuple, msg *sipMessage) {
    debugf("Processing query. %s", tuple.String())

    trans := sip.deleteTransaction(tuple.hashable())
    if trans != nil {
        // This happens if a client puts multiple requests in flight
        // with the same ID.
        trans.notes = append(trans.notes, "duplicateQueryMsg.Error()")
        debugf("%s %s", "duplicateQueryMsg.Error()", tuple.String())
        sip.publishTransaction(trans)
        sip.deleteTransaction(trans.tuple.hashable())
    }

    trans = newTransaction(msg.ts, *tuple, *msg.cmdlineTuple)

// コンパイル通すためにいったんコメントアウト
//    if tuple.transport == transportUDP && (msg.data.IsEdns0() != nil) && msg.length > maxSIPPacketSize {
//        trans.notes = append(trans.notes, "udpPacketTooLarge.Error()")
//        debugf("%s", "udpPacketTooLarge.Error()")
//    }

    sip.transactions.Put(tuple.hashable(), trans)
    trans.request = msg
}

func (sip *sipPlugin) receivedSIPResponse(tuple *sipTuple, msg *sipMessage) {
    debugf("Processing response. %s", tuple.String())

    trans := sip.getTransaction(tuple.revHashable())
    if trans == nil {
        trans = newTransaction(msg.ts, tuple.reverse(), common.CmdlineTuple{
            Src: msg.cmdlineTuple.Dst, Dst: msg.cmdlineTuple.Src})
        trans.notes = append(trans.notes, "orphanedResponse.Error()")
        debugf("%s %s", "orphanedResponse.Error()", tuple.String())
        unmatchedResponses.Add(1)
    }

    trans.response = msg

    if tuple.transport == transportUDP {
// コンパイル通すためにいったんコメントアウト
//        respIsEdns := msg.data.IsEdns0() != nil
//        if !respIsEdns && msg.length > maxSIPPacketSize {
//            trans.notes = append(trans.notes, udpPacketTooLarge.responseError())
//            debugf("%s", udpPacketTooLarge.responseError())
//        }
//
//        request := trans.request
//        if request != nil {
//            reqIsEdns := request.data.IsEdns0() != nil
//
//            switch {
//            case reqIsEdns && !respIsEdns:
//                trans.notes = append(trans.notes, respEdnsNoSupport.Error())
//                debugf("%s %s", respEdnsNoSupport.Error(), tuple.String())
//            case !reqIsEdns && respIsEdns:
//                trans.notes = append(trans.notes, respEdnsUnexpected.Error())
//                debugf("%s %s", respEdnsUnexpected.Error(), tuple.String())
//            }
//        }
    }

    sip.publishTransaction(trans)
    sip.deleteTransaction(trans.tuple.hashable())
}

// publishTransactionはひとつのトランザクションを
// Elasticsearchに書き出すためのデータを作る過程
func (sip *sipPlugin) publishTransaction(t *sipTransaction) {
    if sip.results == nil {
        return
    }

    debugf("Publishing transaction. %s", t.tuple.String())

    timestamp := t.ts
    fields := common.MapStr{}
    fields["type"] = "sip"
    fields["transport"] = t.transport.String()
    fields["src"] = &t.src
    fields["dst"] = &t.dst
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

// トランザクションがタイムアウトした時の処理
func (sip *sipPlugin) expireTransaction(t *sipTransaction) {
    t.notes = append(t.notes, "noResponse.Error()")
    debugf("%s %s", "noResponse.Error()", t.tuple.String())
    sip.publishTransaction(t)
    unmatchedRequests.Add(1)
}

// decodeSIPData decodes a byte array into a SIP struct. If an error occurs
// then the returned sip pointer will be nil. This method recovers from panics
// and is concurrency-safe.
//func (sip *sipPlugin) decodeSIPData(ts time.Time, tuple common.IPPortTuple, cmdlineTuple *common.CmdlineTuple, transp transport, rawData []byte) (msg *sipMessage, err error) {
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

    sipMsg, err:= sip.createSIPMessage(transportUDP, pkt.Payload)
    sipMsg.parseSIPHeader()
    if sipMsg.bdy_start < sipMsg.bdy_end {
        sipMsg.parseSIPBody()
    }

    //
    if sipMsg.bdy_end != -1{
    }
    fmt.Printf("%s\n",sipMsg)
    _ = err

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
}
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
