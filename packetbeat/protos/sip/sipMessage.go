package sip

import (
    "fmt"
    "strconv"
    "strings"
    "time"

	"github.com/elastic/beats/libbeat/common"
)

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
    transport    transport

    // SIP FirstLines
    isRequest    bool
    method       common.NetString
    requestUri   common.NetString
    statusCode   uint16
    statusPhrase common.NetString

    // SIP Headers
    from            common.NetString
    to              common.NetString
    cseq            common.NetString
    callid          common.NetString
    headers         *map[string][]common.NetString
    contentlength   int

    // SIP Bodies
    body      map[string]*map[string][]common.NetString

    // Raw Data
    raw          []byte

    // Offsets
    hdr_start    int
    hdr_len      int
    bdy_start    int

}

func (msg sipMessage) String() string {
    outputs:=""
    outputs+=fmt.Sprintf("%s:Src:%s:%d -> Dst:%s:%d ,", msg.ts, 
                                                        msg.tuple.SrcIP,
                                                        msg.tuple.SrcPort,
                                                        msg.tuple.DstIP,
                                                        msg.tuple.DstPort)
    if msg.isRequest{
        outputs+="Request: ("
        outputs+=string(msg.method)
        outputs+=", "
        outputs+=string(msg.requestUri)
        outputs+="), "
    }else{
        outputs+="Response: ("
        outputs+=fmt.Sprintf("%03d",msg.statusCode)
        outputs+=", "
        outputs+=string(msg.statusPhrase)
        outputs+="), "
    }
    outputs+=" From   : "+string(msg.from)   + ", "
    outputs+=" To     : "+string(msg.to)     + ", "
    outputs+=" CSeq   : "+string(msg.cseq)   + ", "
    outputs+=" Call-ID: "+string(msg.callid) + ", "
    outputs+=" Headers: ["
    for header,array := range *(msg.headers){
        for idx,line:= range array{
            outputs+=fmt.Sprintf(" { %20s[%3d] : %s} ",header,idx,line)
        }
    }
    outputs+=", body: "
    for body,maps_p := range msg.body{
        outputs+=fmt.Sprintf("{ %s : ",body)
        if(body == "application/sdp"){
            for key,lines:= range *maps_p{
                for idx,line:= range lines{
                    outputs+=fmt.Sprintf("  { %5s[%3d] : %s } ",key,idx,line)
                }
            }
        }
        outputs+=fmt.Sprintf(" }")
    }
    return outputs
}
func (msg *sipMessage) parseSIPHeader() (err error){
    msg.hdr_start    =-1
    msg.hdr_len      =-1
    msg.bdy_start    =-1
    msg.contentlength=-1


    // SIPのヘッダとボディの区切りとそれまでのCRLFで改行が入っている箇所を探す
    cutPosS := []int{} // SIPメッセージの先頭、またはCRLFの直後のバイト位置
    cutPosE := []int{} // CRLFの直前のバイト位置

    byte_len := len(msg.raw)
    hdr_start:=-1       // SIPメッセージの始まり位置を-1で初期化
    hdr_end  :=-1 // SIPのボディの終了位置(CRLFCRLF)位置を受け取ったbyte arrayの長さで初期化
    bdy_start:=byte_len // SIPのボディの終了位置(CRLFCRLF)位置を受け取ったbyte arrayの長さで初期化

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
    if hdr_start < 0 {
        //CRLFしかないパケット
        return fmt.Errorf("malformed packet")
    }
    if hdr_end < 0 {
        //ヘッダ途中でフラグメントされた（と思しき）パケット
        //TODO:SIPパケットでない可能性もあり。
        return nil
    }
   
    // この時点でSIPパケットじゃないことは確定
    msg.hdr_len  =hdr_end - hdr_start
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
        return fmt.Errorf("malformed packet(thi is not sip messages)")
    }

    // Content-Lenghtは0でいったん初期化
    msg.contentlength = 0
    contenttype_array  , existContentType   := (*headers)["content-type"]
    contentlength_array, existContentLength := (*headers)["content-length"]
    _ = contenttype_array

    contentlength:=0

    // Content-Lengthが存在する場合
    // 取得を試みる。失敗した場合は0でリセットする
    if existContentLength{
        raw_cnt_len,err_cnt_len := strconv.ParseInt(string(getLastElementStrArray(contentlength_array)),10,64)
        contentlength=int(raw_cnt_len)

        // Content-Lengthが不正文字列の場合は
        // 無視して0で初期化
        if err_cnt_len!= nil{
            contentlength=0
        }
    }

    // Content-typeはBodyがある場合は存在するはずなので
    // Content-Typeが存在しない場合はBody無しとして
    // ヘッダの後のデータは無視する(RFC 3261 20.15)
    if !existContentType{
        contentlength=0
    }

    msg.contentlength=contentlength

    if msg.bdy_start + msg.contentlength > byte_len {
        // TODO:
        // fragmented packetの場合、未受信部分があるのでバッファリングの処理に入る・・・かな？
        // とりあえず現状は取れる分だけとっとく。
        // 
        msg.contentlength=-1
    }

    return nil
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

// SIPボディのパース処理
// TODO:Content-Encoding時の処理を記載(RFC3261)
func (msg *sipMessage) parseSIPBody() (err error){

    contenttype_array  , hd_ctype_ok   := (*msg.headers)["content-type"]

    // content-typeがない場合はreturnして終了
    if !hd_ctype_ok {
        debugf("This sip message has not body.")
        return fmt.Errorf("invalid call")
    }

    msg.body=map[string]*map[string][]common.NetString{}

    // bodyの種類により動作を変更する
    lower_case_content_type:=strings.ToLower(string(getLastElementStrArray(contenttype_array)))
    switch(lower_case_content_type){
        case "application/sdp":
            body,err:=msg.parseBody_SDP(msg.raw[msg.bdy_start:msg.bdy_start+msg.contentlength])
            _ = err
            if err != nil{
                debugf("%s : parseError",lower_case_content_type)
                return fmt.Errorf("Parse error")
            }

            msg.body[lower_case_content_type]=body

        default:
            debugf("unspported content-type. : %s",lower_case_content_type)
            return fmt.Errorf("Parse error")

    }

    return  nil
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

