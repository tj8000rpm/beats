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

    // Additional Information
    notes        []common.NetString

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

    if msg.headers != nil{
        outputs+=" Headers: ["
        for header,array := range *(msg.headers){
            for idx,line:= range array{
                outputs+=fmt.Sprintf(" { %20s[%3d] : %s} ",header,idx,line)
            }
        }
    }
    if msg.body != nil{
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

    //CRLFしかないパケット
    if hdr_start < 0 {
        return fmt.Errorf("malformed packet")
    }
    //ヘッダ途中でフラグメントされた（と思しき）パケット
    if hdr_end < 0 {
        //TODO:SIPパケットでない可能性もあり。
        return nil
    }
   
    msg.hdr_len  =hdr_end - hdr_start
    msg.bdy_start=bdy_start

    // 正常系処理
    // SIP
    headers, start_line:=msg.parseSIPHeaderToMap(cutPosS,cutPosE)

    // リクエストかレスポンスかを判定
    if len(start_line) != 3{
        msg.notes = append(msg.notes,common.NetString("start line parse error."))
        return fmt.Errorf("malformed packet")
    }

    msg.isRequest = strings.Contains(start_line[2],"SIP/2.0")
    if msg.isRequest {
        msg.method    =common.NetString(start_line[0])
        msg.requestUri=common.NetString(start_line[1])
    }else if strings.Contains(start_line[0],"SIP/2.0") { // Response
        parsedStatusCode,err := strconv.ParseInt(start_line[1],10,16)
        if err !=nil {
            msg.statusCode  =uint16(999)
            msg.notes = append(msg.notes,common.NetString(fmt.Sprintf("invalid status-code %s",start_line[1])))
        }else{
            msg.statusCode  =uint16(parsedStatusCode)
        }
        msg.statusPhrase=common.NetString(strings.TrimSpace(start_line[2]))
    }else{
        msg.notes = append(msg.notes,common.NetString("malformed packet. this is not sip message."))
        return fmt.Errorf("malformed packet(this is not sip message)")
    }

    // mandatory header fields check
    to_array         , existTo          := (*headers)["to"          ]
    from_array       , existFrom        := (*headers)["from"        ]
    cseq_array       , existCSeq        := (*headers)["cseq"        ]
    callid_array     , existCallId      := (*headers)["call-id"     ]
    maxfrowards_array, existMaxForwards := (*headers)["max-forwards"]
    via_array        , existVia         := (*headers)["via"         ]

    // 必須ヘッダ不足
    if existTo {
        msg.to    =getLastElementStrArray(to_array)
    }else{
        msg.notes = append(msg.notes,common.NetString("mandatory header [To] does not exist."))
    }

    if existFrom {
        msg.from  =getLastElementStrArray(from_array)
    }else{
        msg.notes = append(msg.notes,common.NetString("mandatory header [From] does not exist."))
    }

    if existCSeq{
        msg.cseq  =getLastElementStrArray(cseq_array)
    }else{
        msg.notes = append(msg.notes,common.NetString("mandatory header [CSeq] does not exist."))
    }

    if existCallId{
        msg.callid=getLastElementStrArray(callid_array)
    }else{
        msg.notes = append(msg.notes,common.NetString("mandatory header [Call-ID] does not exist."))
    }

    if ! existMaxForwards{
    }
    if ! existVia{
        msg.notes = append(msg.notes,common.NetString("mandatory header [Via] does not exist."))
    }

    // headers value update
    msg.headers=headers

    // unused
    _=maxfrowards_array
    _=via_array

    // Content-Lenght initialized to 0
    msg.contentlength = 0
    contenttype_array  , existContentType   := (*headers)["content-type"]
    contentlength_array, existContentLength := (*headers)["content-length"]
    _ = contenttype_array

    contentlength:=0

    if existContentType{
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
        } else {
            contentlength=byte_len - bdy_start
        }
    } else {
    // Content-typeはBodyがある場合は存在するはずなので
    // Content-Typeが存在しない場合はBody無しとして
    // ヘッダの後のデータは無視する(RFC 3261 20.15)
        contentlength=0
    }

    msg.contentlength=contentlength

    if msg.bdy_start + msg.contentlength > byte_len {
        // ボディが未受信の場合はボディ未受信を表すために
        // contentlength=-1を設定し、バッファリングし
        // 再度SIPとしてパースするようにする
        msg.contentlength=-1
    }

    // 問題なければerr=nil
    return nil
}

/**
 * commaSeparatedStringに指定された文字列（カンマ区切り）を,位置で区切り、
 * 区切った後の文字列の前後のスペースを排除したNetStringの配列に変更する
 *
 * example:
 * commaSeparatedString : ,aaaa,"bbbb,ccc",hoge\,hige,\"aa,aa\",
 * separatedStrings : 
 *   -            // カンマで始まっている部分は前に空文字を追加する
 *   - aaaa
 *   -"bbbb,cccc" // "で区切られた部分はセパレートしない
 *   - hoge\,hige // エスケープされた,はセパレートしない
 *   - \"aa       // エスケープされた"で区切られた部分はセパレートする
 *   - aa\"       // 同上
 *   -            // カンマで終わっている部分は後ろに空文字を追加する
 *
 *  example2:
 *  commaSeparatedString : aaaa,"aaaaa,bbb
 *  separatedStrings :
 *    - aaaa
 *    - "aaaaa,bbb  //エスケープされたとちゅうデモ書き出し
 **/
func (msg *sipMessage) separateCsv(commaSeparatedString string) (separatedStrings *[]common.NetString){
    separatedStrings = &[]common.NetString{}
    var prevChar rune
    startIdx:=0
    insubcsv:=false
    escaped:=false
    for idx,curChar := range commaSeparatedString{
        /* escaped boolの動き
         *   time|01234567
         * ------+--------
         *   char| \\"\\\"
         * ------+--------
         * x=!esc| TFTTFTF //
         * y=c==\| TTFTTTF // prevChar==\\の結果
         * ------+--------
         *   x&&y|FTFFTFTF // escaped boolの計算結果
        */
        escaped=(!escaped && prevChar == '\\')
        finalChr :=(idx+1 == len(commaSeparatedString))
        isComma:=(curChar == ',')

        if curChar == '"' && !escaped{
            insubcsv=!insubcsv
        }

        if finalChr {
            if isComma && !insubcsv { 
                subStr:=strings.TrimSpace(commaSeparatedString[startIdx:idx])
                *separatedStrings=append(*separatedStrings, common.NetString(subStr))
                *separatedStrings=append(*separatedStrings, common.NetString(""))
            }else{
                subStr:=strings.TrimSpace(commaSeparatedString[startIdx:idx+1])
                *separatedStrings=append(*separatedStrings, common.NetString(subStr))
            }
        } else if !insubcsv && (!escaped && isComma){
            subStr:=strings.TrimSpace(commaSeparatedString[startIdx:idx])
            *separatedStrings=append(*separatedStrings, common.NetString(subStr))

            startIdx=idx+1
        }
        prevChar=curChar
    }

    return separatedStrings
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
            // みたいなケースに対応
            if msg.raw[s] == byte(' ') || msg.raw[s] == byte('\t'){
                if lastheader!=""{
                    lastElement:=string(getLastElementStrArray((*headers)[lastheader]))
                    // TrimSpaceは" "と"\t"の両方削除してくれる
                    lastElement+=fmt.Sprintf(" %s",strings.TrimSpace(string(msg.raw[s:e])))
                    (*headers)[lastheader][len((*headers)[lastheader])-1]=common.NetString(lastElement)
                }else{
                    // 当該行を無視する
                }
                continue
            }

            // 前回処理した場所は改行箇所であった部分で,区切りを探す
            // Process 342
            if lastheader!=""{
                lastHeaderEndIdx:=len((*headers)[lastheader])-1
                if lastHeaderEndIdx < 0 {continue} // ないはずだけど・・・

                lastElement:=string(getLastElementStrArray((*headers)[lastheader]))
                separatedStrings:=msg.separateCsv(lastElement)
                for idx,element := range *separatedStrings {
                    if idx == 0{
                        (*headers)[lastheader][lastHeaderEndIdx]=element
                    }else{
                        (*headers)[lastheader]=append((*headers)[lastheader],element)
                    }
                }
            }

            // 先頭がスペースまたはタブ出ない時はヘッダパラメータのはず
            header_kv:=strings.SplitN(string(msg.raw[s:e]),":",2)
            key:=strings.ToLower(strings.TrimSpace(header_kv[0]))
            val:=strings.TrimSpace(header_kv[1])

            // 分割の結果:が含まれていない場合
            if val == ""{
                continue
            }

            // 初登場のヘッダの場合はマップを初期化
            _,ok := (*headers)[key]
            if !ok{
                (*headers)[key]=[]common.NetString{}
            }

            (*headers)[key]=append((*headers)[key],common.NetString(val))
            lastheader=key
        }
        // 最終要素でもカンマ区切りを探す
        // FIXME: Same Process 342...
        if lastheader!=""{
            lastHeaderEndIdx:=len((*headers)[lastheader])-1
            if lastHeaderEndIdx < 0 {continue} // ないはずだけど・・・

            lastElement:=string(getLastElementStrArray((*headers)[lastheader]))
            separatedStrings:=msg.separateCsv(lastElement)
            for idx,element := range *separatedStrings {
                if idx == 0{
                    (*headers)[lastheader][lastHeaderEndIdx]=element
                }else{
                    (*headers)[lastheader]=append((*headers)[lastheader],element)
                }
            }
        }
    }
    return headers, first_lines
}

// SIPボディのパース処理
// TODO:Content-Encoding時の処理(RFC3261) 未実装
func (msg *sipMessage) parseSIPBody() (err error){
    // in case no called before parseSIPHeader
    if (msg.headers) == nil{
        debugf("parseSIPBody: This sip message's .headers is nill.")
        return fmt.Errorf("headers is nill")
    }

    if msg.contentlength <= 0{
        return nil
     }

    contenttype_array  , hd_ctype_ok   := (*msg.headers)["content-type"]

    // content-typeがない場合はreturnして終了
    if !hd_ctype_ok {
        debugf("parseSIPBody: This sip message has not body.")
        return fmt.Errorf("no content-type header")
    }

    msg.body=map[string]*map[string][]common.NetString{}

    if len(contenttype_array) == 0{
        //contenttype_array has no element
        return nil
    }

    // bodyの種類により動作を変更する
    lower_case_content_type:=strings.ToLower(string(getLastElementStrArray(contenttype_array)))
    switch(lower_case_content_type){
        case "application/sdp":
            body,err:=msg.parseBody_SDP(msg.raw[msg.bdy_start:msg.bdy_start+msg.contentlength])
            _ = err
            if err != nil{
                debugf("%s : parseError",lower_case_content_type)
                return fmt.Errorf("invalid %s format.",lower_case_content_type)
            }

            msg.body[lower_case_content_type]=body

        default:
            debugf("unsupported content-type. : %s",lower_case_content_type)
            return fmt.Errorf("unsupported content-type")
    }

    return  nil
}

func (msg *sipMessage) parseBody_SDP(rawData []byte) (body *map[string][]common.NetString, err error){
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

func (msg *sipMessage) getMessageStatus() (int){
    if msg.hdr_start < 0 { return SIP_STATUS_REJECTED}
    if msg.hdr_len   < 0 { return SIP_STATUS_HEADER_RECEIVING}
    if msg.contentlength < 0 { return SIP_STATUS_BODY_RECEIVING}
    return SIP_STATUS_RECEIVED
}
