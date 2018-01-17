#### 実装方針
- SIPは呼の長さがいくつになるかわからないため、
  call単位でのまとめ(例えばFinal Responseがなんであったのかや応答時間など)
  は求めず、リクエスト、またはレスポンスいそれぞれを
  一つのメッセージとし、メッセージの受信が完了した時点で
  パケットキャプチャの結果として書き出すこととする。
- CallごとのシーケンスなどはElasticsearch側で工夫してもらうものとする

- キャプチャ結果には以下を含む


#### Sample JSON Output
```json
{
   "_index": "packetbeat-7.0.0-alpha1-2018.01.17",
   "_type": "doc",
   "_id": "14uKBGEBLUdHmvOi5U1L",
   "_score": null,
   "_source": {
     "@timestamp": "2018-01-17T14:34:26.016Z",
     "beat": {
       "name": "Elasticsearch1",
       "hostname": "Elasticsearch1",
       "version": "7.0.0-alpha1"
     },
     "sip.headers": {
       "from": [
         "sipp <sip:sipp@192.168.0.220:5060>;tag=26730SIPpTag003138"
       ],
       "to": [
         "service <sip:service@127.0.0.1:5060>"
       ],
       "cseq": [
         "1 INVITE"
       ],
       "subject": [
         "Performance Test"
       ],
       "contact": [
         "sip:sipp@192.168.0.220:5060"
       ],
       "content-type": [
         "application/sdp"
       ],
       "call-id": [
         "3138-26730@192.168.0.220"
       ],
       "content-length": [
         "137"
       ],
       "via": [
         "SIP/2.0/UDP 192.168.0.220:5060;branch=z9hG4bK-26730-3138-0"
       ],
       "max-forwards": [
         "70"
       ]
     },
     "sip.body": {
       "application/sdp": {
         "o": [
           "user1 53655765 2353687637 IN IP4 192.168.0.220"
         ],
         "s": [
           "-"
         ],
         "c": [
           "IN IP4 192.168.0.220"
         ],
         "t": [
           "0 0"
         ],
         "m": [
           "audio 6000 RTP/AVP 0"
         ],
         "a": [
           "rtpmap:0 PCMU/8000"
         ],
         "v": [
           "0"
         ]
       }
     },
     "sip.request_uri": "sip:service@127.0.0.1:5060",
     "sip.call_id": "3138-26730@192.168.0.220",
     "sip.cseq": "1 INVITE",
     "sip.dst": "127.0.0.1:5060",
     "sip.unixtimenano": 1516199666016756000,
     "type": "sip",
     "sip.method": "INVITE",
     "sip.from": "sipp <sip:sipp@192.168.0.220:5060>;tag=26730SIPpTag003138",
     "sip.to": "service <sip:service@127.0.0.1:5060>",
     "sip.raw": """
INVITE sip:service@127.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.0.220:5060;branch=z9hG4bK-26730-3138-0
From: sipp <sip:sipp@192.168.0.220:5060>;tag=26730SIPpTag003138
To: service <sip:service@127.0.0.1:5060>
Call-ID: 3138-26730@192.168.0.220
CSeq: 1 INVITE
Contact: sip:sipp@192.168.0.220:5060
Max-Forwards: 70
Subject: Performance Test
Content-Type: application/sdp
Content-Length:   137

v=0
o=user1 53655765 2353687637 IN IP4 192.168.0.220
s=-
c=IN IP4 192.168.0.220
t=0 0
m=audio 6000 RTP/AVP 0
a=rtpmap:0 PCMU/8000

""",
    "sip.src": "192.168.0.220:5060",
    "sip.transport": "udp"
  }
}
```

#### UDP



#### TCP

no supported yet.

#### TODO

* SIPカンマ区切りのものを複数に分割する
* Content-encodeの場合をどうするか
* TCPは後回しとする
* テストケースを作る
* その他いろいろ思いついたら追記する
