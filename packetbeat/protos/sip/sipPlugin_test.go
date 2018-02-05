package sip

import (
    "testing"

    "github.com/elastic/beats/libbeat/common"

    "github.com/stretchr/testify/assert"
)


func TestInit(t *testing.T) {// error {
}

func TestSetFromConfig(t *testing.T) {//(config *sipConfig) error {
    sip:=sipPlugin{}
    cfg:=sipConfig{}
    cfg.Ports=[]int{5060,5061}
    cfg.BufferTimeout=30

    sip.setFromConfig(&cfg)
    assert.Equal(t, 30   , int(sip.fragmentBufferTimeout) , "There should be 30." )
    assert.Equal(t, 5060 , sip.ports[0]                   , "There should be included 5060." )
    assert.Equal(t, 5061 , sip.ports[1]                   , "There should be included 5061." )
}

func TestGetPorts(t *testing.T) {
    sip:=sipPlugin{}
    sip.ports=[]int{5060,5061,1123,5555}
    ports:=sip.GetPorts()

    assert.Equal(t, 5060 , ports[0]                   , "There should be included 5060." )
    assert.Equal(t, 5061 , ports[1]                   , "There should be included 5061." )
    assert.Equal(t, 1123 , ports[2]                   , "There should be included 5061." )
    assert.Equal(t, 5555 , ports[3]                   , "There should be included 5061." )
}

func TestAddBuffer(t *testing.T) {//(k hashableSIPTuple,buffer *sipBuffer) {
    sip:=sipPlugin{}
    buf:=sipBuffer{}
    hash:=hashableSIPTuple{}
    hash2:=hashableSIPTuple{}
    hash2[0]=1

    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        /* buffer time for fragmented udp packets. */ 30,
        /* buffer size for fragmented udp packets. */ 10,
        func(k common.Key, v common.Value) {    // callback function when remove buffer.
            return
        })
    sip.fragmentBuffer.StartJanitor(30)

    assert.Equal(t, 0 , sip.fragmentBuffer.Size()                   , "There should be empty." )
    sip.addBuffer(hash,&buf)
    assert.Equal(t, 1 , sip.fragmentBuffer.Size()                   , "There should be one element." )
    // dupulicate hash
    sip.addBuffer(hash,&buf)
    assert.Equal(t, 1 , sip.fragmentBuffer.Size()                   , "There should not change." )
    // another hash
    sip.addBuffer(hash2,&buf)
    assert.Equal(t, 2 , sip.fragmentBuffer.Size()                   , "There should be two element." )
}

func TestGetBuffer(t *testing.T) {//(k hashableSIPTuple) *sipBuffer {
}

func TestDeleteBuffer(t *testing.T) {// (k hashableSIPTuple) *sipBuffer {
}

func TestExpireBuffer(t *testing.T) {// (t *sipBuffer) {
}

func TestConnectionTimeout(t *testing.T) {// () time.Duration {
}

func TestPublishMessage(t *testing.T) {// (msg *sipMessage) {
}

func TestSipTupleFromIPPort(t *testing.T) {// (t *common.IPPortTuple, trans transport) sipTuple {
}

func TestCreateSIPMessage(t *testing.T) {// (transp transport, rawData []byte) (msg *sipMessage, err error) {
}

func TestNewBuffer(t *testing.T) {// (ts time.Time, tuple sipTuple, cmd common.CmdlineTuple,msg *sipMessage) *sipBuffer {
}

func TestParseUDP(t *testing.T) {// (pkt *protos.Packet) {
}

