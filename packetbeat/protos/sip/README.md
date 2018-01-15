#### 実装方針
- SIPは呼の長さがいくつになるかわからないため、
  call単位でのまとめ(例えばFinal Responseがなんであったのかや応答時間など)
  は求めず、リクエスト、またはレスポンスいそれぞれを
  一つのメッセージとし、メッセージの受信が完了した時点で
  パケットキャプチャの結果として書き出すこととする。
- CallごとのシーケンスなどはElasticsearch側で工夫してもらうものとする

- キャプチャ結果には以下を含む

```yaml
fields :
  type:sip
  transport: udp or tcp
  src: SrcIP:SrcPort
  dst: DstIP:DstPort

  method: INVITE,ACK,BYE,etc... // only request msg.
  request_uri: <sip:example@example.com:5060> // only requst msg.

  status_code: 200,180,100,etc... // only response msg.
  status_phrase: OK,Ringing,etc... // only response msg.

  from: mandatoryHeader
  to: mandatoryHeader
  cseq: mandatoryHeader
  call_id: mandatoryHeader

  headers: // all header include
    via:
     - Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339
     - Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK2312101233
    content-type:
     - application/sdp
    // etc...

  body: // all body include(if supporte)
    application/sdp:
      a:
        - rtpmap:0 PCMU/8000
        - rtpmap:18 G729/8000
    // etc...
```

#### UDP



#### TCP

no supported yet.

#### TODO

* TCPは後回しとする
* テストケースを作る
* その他いろいろ思いついたら追記する
