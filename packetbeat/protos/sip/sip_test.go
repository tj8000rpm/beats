// +build !integration

package sip

import (
    "net"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"

    "github.com/elastic/beats/libbeat/beat"
    "github.com/elastic/beats/libbeat/common"
    "github.com/elastic/beats/libbeat/logp"
    "github.com/elastic/beats/packetbeat/protos"
)

// Test Constants
const (
    serverIP   = "192.168.0.1"
    serverPort = 5060
    clientIP   = "10.0.0.1"
    clientPort = 5060
)

// DnsTestMessage holds the data that is expected to be returned when parsing
// the raw DNS layer payloads for the request and response packet.
type sipTestMessage struct {
    // request     []byte
    // response    []byte
    messages    [][]byte
}

// Request and response addresses.
var (
    forward = common.NewIPPortTuple(4,
        net.ParseIP(serverIP), serverPort,
        net.ParseIP(clientIP), clientPort)
    reverse = common.NewIPPortTuple(4,
        net.ParseIP(clientIP), clientPort,
        net.ParseIP(serverIP), serverPort)
)

var (
    // An array of all test messages.
    messages = []sipTestMessage{
        test1,
        test2,
        test3,
    }

    test1 = sipTestMessage{
        messages: [][]byte{
                     []byte(  "INVITE sip:0312345678@192.168.0.1;user=phone SIP/2.0\r\n"   +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK81075720\r\n"  +
                              "From: <sip:sipurl@192.168.0.1>;tag=269050131\r\n"           +
                              "To: <sip:0312341234@192.168.0.1;user=phone>\r\n"            +
                              "Contact: <sip:301234123@10.0.0.1;user=phone>\r\n"           +
                              "Call-ID: hogehoge@192.168.0.1\r\n"                          +
                              "CSeq: 1 INVITE\r\n"                                         +
                              "Max-Forwards: 70\r\n"                                       +
                              "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, PRACK\r\n"         +
                              "Supported: 100rel,timer\r\n"                                +
                              "Session-Expires: 300\r\n"                                   +
                              "Privacy: none\r\n"                                          +
                              "P-Preferred-Identity: <tel:0387654321>\r\n"                 +
                              "Content-Type: application/sdp\r\n"                          +
                              "Content-Length: 107\r\n"                                    +
                              "\r\n"                                                       +
                              "v=0\r\n"                                                    +
                              "o=- 0 0 IN IP4 10.0.0.1\r\n"                                +
                              "s=-\r\n"                                                    +
                              "c=IN IP4 10.0.0.1\r\n"                                      +
                              "t=0 0\r\n"                                                  +
                              "m=audio 5012 RTP/AVP 0\r\n"                                 +
                              "a=rtpmap:0 PCMU/8000\r\n"),

                      []byte( "SIP/2.0 407 Proxy Authentication Required\r\n"              +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK3408987398\r\n"+
                              "From: <sip:hogehoge@10.0.0.1>;tag=5408647717\r\n"           +
                              "To: <sip:0312345678@192.168.0.1>;tag=3713480994\r\n"        +
                              "Call-ID: hogehoge@192.168.0.1\r\n"                         +
                              "CSeq: 1 INVITE\r\n"                                         +
                              "Content-Length: 0\r\n"                                      +
                              "Date: Mon, 04 Sep 2017 02:29:54 GMT\r\n"                    +
                              "Proxy-Authenticate: Digest realm=\"example.com\","          + // 改行していない
                              " domain=\"sip:192.168.0.1\", nonce=\"15044921123142536\","  + // 改行していない
                              " opaque=\"\", stale=FALSE, algorithm=MD5\r\n"               +
                              "\r\n"),

                     []byte(  "ACK sip:0312345678@192.168.0.1:5060 SIP/2.0\r\n"               +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK3408987398\r\n"   +
                              "From: <sip:hogehoge@example.com>;tag=5408647717\r\n"           +
                              "To: <sip:0312345678@192.168.0.1>;tag=3713480994\r\n"           +
                              "Call-ID: hogehoge@10.0.0.1\r\n"                                +
                              "CSeq: 1 ACK\r\n"                                               +
                              "Content-Length: 0\r\n"                                         +
                              "Max-Forwards: 70\r\n"                                          +
                              "\r\n"),

                     []byte(  "INVITE sip:0312345678@192.168.0.1:5060 SIP/2.0\r\n"                        +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339\r\n"               +
                              "From: <sip:hogehoge@example.cm>;tag=1451088881\r\n"                        +
                              "To: <sip:0312345678@192.168.0.1>\r\n"                                      +
                              "Call-ID: hogehoge@10.0.0.1\r\n"                                            +
                              "CSeq: 2 INVITE\r\n"                                                        +
                              "Contact: <sip:1833176976@10.0.0.1:5060;transport=udp>\r\n"                 +
                              "Supported: 100rel, timer\r\n"                                              +
                              "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, PRACK\r\n"                        +
                              "Content-Length: 134\r\n"                                                   +
                              "Session-Expires: 180\r\n"                                                  +
                              "Max-Forwards: 70\r\n"                                                      +
                              "Content-Type: application/sdp\r\n"                                         +
                              "Privacy: none\r\n"                                                         +
                              "P-Preferred-Identity: <sip:hogehoge@example.com>\r\n"                    +
                              "User-Agent: Some User-Agent\r\n"                                           +
                              "Proxy-Authorization: Digest username=\"hogehoge\", realm=\"example.com\"," + // 改行していない
                              " nonce=\"15044921123142536\", uri=\"sip:0312345678@192.168.0.1:5060\","    + // 改行していない
                              " response=\"358a640a266ad4eb3ed82f0746c82dfd\"\r\n"                        +
                              "\r\n"                                                                      +
                              "v=0\r\n"                                                                   +
                              "o=- 0 0 IN IP4 10.0.0.1\r\n"                                               +
                              "s=-\r\n"                                                                   +
                              "c=IN IP4 10.0.0.1\r\n"                                                     +
                              "t=0 0\r\n"                                                                 +
                              "m=audio 10000 RTP/AVP 0 18\r\n"                                            +
                              "a=rtpmap:0 PCMU/8000\r\n"                                                  +
                              "a=rtpmap:18 G729/8000\r\n"),
                  },
    }
    test2 = sipTestMessage{ // Fragmented Packet, fragmented at header
        messages: [][]byte{
                     []byte(  "INVITE sip:0312345678@192.168.0.1:5060 SIP/2.0\r\n"                        +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339\r\n"               +
                              "From: <sip:hogehoge@example.cm>;tag=1451088881\r\n"                        +
                              "To: <sip:0312345678@192.168.0.1>\r\n"                                      +
                              "Call-ID: hogehoge@10.0.0.1\r\n"                                            +
                              "CSeq: 2 INVITE\r\n"                                                        +
                              "Contact: <sip:1833176976@10.0.0.1:5060;transport=udp>\r\n"                 +
                              "Supported: 100rel, timer\r\n"                                              +
                              "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, PRACK\r\n"                        +
                              "Content-Length: 134\r\n"                                                   +
                              "Session-Expires: 180\r\n"                                                  +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339\r\n"               +
                              "Max-Forwards: 70\r\n"                                                      +
                              "Content-Type: application/sdp\r\n"                                         +
                              "Privacy: none\r\n"                                                         +
                              "P-Preferred-Identity: <sip:hogehoge@example.com>\r\n"                    +
                              "User-Agent: Some User-Agent\r\n"                                           +
                              "Proxy-Authorization: Digest username=\"hogehoge\", realm=\"example.com\"," + // 改行していない
                              " nonce=\"15044921123142536\", uri=\"sip:0312345678@192.168.0.1:5060\","    + // 改行していない
                              " response=\"358a640a266ad4eb3ed82f0746c82dfd\"\r\n"                        +
                              "\r\n"                                                                      +
                              "v=0\r\n" ),

                      []byte( "o=- 0 0 IN IP4 10.0.0.1\r\n"                                               +
                              "s=-\r\n"                                                                   +
                              "c=IN IP4 10.0.0.1\r\n"                                                     +
                              "t=0 0\r\n"                                                                 +
                              "m=audio 10000 RTP/AVP 0 18\r\n"                                            +
                              "a=rtpmap:0 PCMU/8000\r\n"                                                  +
                              "a=rtpmap:18 G729/8000\r\n"),
        },
    }

    test3 = sipTestMessage{ // Fragmented Packet, fragmented at body
        messages: [][]byte{
                     []byte(  "INVITE sip:0312345678@192.168.0.1:5060 SIP/2.0\r\n"                        +
                              "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339\r\n"               +
                              "From: <sip:hogehoge@example.cm>;tag=1451088881\r\n"                        +
                              "To: <sip:0312345678@192.168.0.1>\r\n"                                      +
                              "Call-ID: hogehoge@10.0.0.1\r\n"                                            +
                              "CSeq: 2 INVITE\r\n"                                                        +
                              "Contact: <sip:1833176976@10.0.0.1:5060;transport=udp>\r\n"                 +
                              "Supported: 100rel, timer\r\n"                                              +
                              "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, PRACK\r\n"                        +
                              "Content-Length: 134\r\n"                                                   +
                              "Session-Expires: 180\r\n"),

                     []byte(  "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1701109339\r\n"               +
                              "Max-Forwards: 70\r\n"                                                      +
                              "Content-Type: application/sdp\r\n"                                         +
                              "Privacy: none\r\n"                                                         +
                              "P-Preferred-Identity: <sip:hogehoge@example.com>\r\n"                    +
                              "User-Agent: Some User-Agent\r\n"                                           +
                              "Proxy-Authorization: Digest username=\"hogehoge\", realm=\"example.com\"," + // 改行していない
                              " nonce=\"15044921123142536\", uri=\"sip:0312345678@192.168.0.1:5060\","    + // 改行していない
                              " response=\"358a640a266ad4eb3ed82f0746c82dfd\"\r\n"                        +
                              "\r\n"                                                                      +
                              "v=0\r\n"                                                                   +
                              "o=- 0 0 IN IP4 10.0.0.1\r\n"                                               +
                              "s=-\r\n"                                                                   +
                              "c=IN IP4 10.0.0.1\r\n"                                                     +
                              "t=0 0\r\n"                                                                 +
                              "m=audio 10000 RTP/AVP 0 18\r\n"                                            +
                              "a=rtpmap:0 PCMU/8000\r\n"                                                  +
                              "a=rtpmap:18 G729/8000\r\n"),
        },
    }
)

type eventStore struct {
    events []beat.Event
}

func (e *eventStore) publish(event beat.Event) {
    e.events = append(e.events, event)
}

func (e *eventStore) empty() bool {
    return len(e.events) == 0
}

func newSIP(store *eventStore, verbose bool) *sipPlugin {
    level := logp.WarnLevel
    if verbose {
        level = logp.DebugLevel
    }
    logp.DevelopmentSetup(
        logp.WithLevel(level),
        logp.WithSelectors("sip"),
    )

    callback := func(beat.Event) {}
    if store != nil {
        callback = store.publish
    }

    cfg, _ := common.NewConfigFrom(map[string]interface{}{
        "ports":               []int{serverPort},
        "buffer_timeout":      5 * time.Second,
    })
    sip, err := New(false, callback, cfg)
    if err != nil {
        panic(err)
    }

    return sip.(*sipPlugin)
}

func newPacket(t common.IPPortTuple, payload []byte) *protos.Packet {
    return &protos.Packet{
        Ts:      time.Now(),
        Tuple:   t,
        Payload: payload,
    }
}

// Verify that an empty packet is safely handled (no panics).
func TestParseUdp_emptyPacket(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet := newPacket(forward, []byte{})
    sip.ParseUDP(packet)
    assert.Empty(t, sip.fragmentBuffer.Size(), "There should be no transactions.")
    assert.True(t, store.empty(), "No result should have been published.")
}

// Verify that a malformed packet is safely handled (no panics).
func TestParseUdp_malformedPacket(t *testing.T) {
    sip := newSIP(nil, testing.Verbose())
    garbage := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
    packet := newPacket(forward, garbage)
    sip.ParseUDP(packet)
    assert.Empty(t, sip.fragmentBuffer.Size(), "There should be no transactions.")

    // As a future addition, a malformed message should publish a result.
}

// Verify that the lone request packet is parsed.
func TestParseUdp_requestPacket(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet := newPacket(forward, test1.messages[0])
    sip.ParseUDP(packet)
    assert.Equal(t, 1, sip.fragmentBuffer.Size(), "There should be one transaction.")
    assert.True(t, store.empty(), "No result should have been published.")
}

func TestParseUdp_responsePacket(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet := newPacket(reverse, test1.messages[1])
    sip.ParseUDP(packet)
    assert.Equal(t, 1, sip.fragmentBuffer.Size(), "There should be one transaction.")
    assert.True(t, store.empty(), "No result should have been published.")
}

func TestParseUdp_requestPacket2(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet := newPacket(reverse, test1.messages[2])
    sip.ParseUDP(packet)
    assert.Equal(t, 1, sip.fragmentBuffer.Size(), "There should be one transaction.")
    assert.True(t, store.empty(), "No result should have been published.")
}

func TestParseUdp_responsePacket2(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet := newPacket(reverse, test1.messages[3])
    sip.ParseUDP(packet)
    assert.Equal(t, 1, sip.fragmentBuffer.Size(), "There should be one transaction.")
    assert.True(t, store.empty(), "No result should have been published.")
}


func TestParseUdp_responseFragmentedPacket2(t *testing.T) {
    store := &eventStore{}
    sip := newSIP(store, testing.Verbose())
    packet1 := newPacket(reverse, test2.messages[0])
    packet2 := newPacket(reverse, test2.messages[1])
    sip.ParseUDP(packet1)
    sip.ParseUDP(packet2)
}


