package sip

import (
    "fmt"
    "net"
)

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
    ipLength          int
    SrcIP, DstIP      net.IP
    SrcPort, DstPort  uint16
    transport         transport

    raw    hashableSIPTuple // SrcIP:SrcPort:DstIP:DstPort:transport
}

//めっちゃハードコードやん・・
// とりあえずDNSとおんなじ方法で
func (t *sipTuple) computeHashebles() {
    copy(t.raw[0:16], t.SrcIP)
    copy(t.raw[16:18], []byte{byte(t.SrcPort >> 8), byte(t.SrcPort)})
    copy(t.raw[18:34], t.DstIP)
    copy(t.raw[34:36], []byte{byte(t.DstPort >> 8), byte(t.DstPort)})
    t.raw[36] = byte(t.transport)
}

func (t sipTuple) String() string {
    return fmt.Sprintf("sipTuple Src[%s:%d] Dst[%s:%d] transport[%s]",
        t.SrcIP.String(),
        t.SrcPort,
        t.DstIP.String(),
        t.DstPort,
        t.transport)
}

// Hashable returns a hashable value that uniquely identifies
// the SIP tuple.
func (t *sipTuple) hashable() hashableSIPTuple {
    return t.raw
}
