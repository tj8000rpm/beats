package sip

import (
    "testing"
    "fmt"
    "net"

    "github.com/elastic/beats/libbeat/common"

    "github.com/stretchr/testify/assert"
)


func TestInit(t *testing.T) {// error {
}

func TestSetFromConfig(t *testing.T) {
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

func TestAddBuffer(t *testing.T) {
    sip:=sipPlugin{}
    buf:=sipBuffer{}
    hash:=hashableSIPTuple{}
    hash2:=hashableSIPTuple{}
    hash2[0]=1

    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        /* buffer time for fragmented udp packets. */ 3000,
        /* buffer size for fragmented udp packets. */ 10,
        func(k common.Key, v common.Value) {    // callback function when remove buffer.
            return
        })
    sip.fragmentBuffer.StartJanitor(3000)

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

func TestGetBuffer(t *testing.T) {
    sip:=sipPlugin{}
    buf:=sipBuffer{transport: transportUDP}
    tuple_ok:=hashableSIPTuple{}
    tuple_ng:=hashableSIPTuple{}
    _ = tuple_ng
    for i:=0;i<len(tuple_ok);i++{tuple_ok[i]=0xff}

    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        /* buffer time for fragmented udp packets. */ 7000,
        /* buffer size for fragmented udp packets. */ 100,
        func(k common.Key, v common.Value) {    // callback function when remove buffer.
            return
        })
    sip.fragmentBuffer.StartJanitor(7000)

    // before status check
    assert.Equal(t, 0 , sip.fragmentBuffer.Size() , "There should be empty." )

    // add the tuple
    sip.addBuffer(tuple_ok,&buf)
    // check after status
    assert.Equal(t, 1 , sip.fragmentBuffer.Size() , "There should be one element." )

    buf_p:=sip.getBuffer(tuple_ok)
    assert.Equal(t, &buf , buf_p                   , "There should be same address." )
    assert.Equal(t, 1 , sip.fragmentBuffer.Size() , "There should be same tuple." )

    // unexist key case, must be nil and shuld not be change buffer size.
    buf_p_nil:=sip.getBuffer(tuple_ng)
    assert.Equal(t, (*sipBuffer)(nil) ,buf_p_nil  , "There should be nil." )
    assert.Equal(t, 1 , sip.fragmentBuffer.Size() , "There should not change." )
}

func TestDeleteBuffer(t *testing.T) {
    sip:=sipPlugin{}
    buf:=sipBuffer{transport: transportUDP}
    tuple_ok:=hashableSIPTuple{}
    tuple_ng:=hashableSIPTuple{}
    _ = tuple_ng
    for i:=0;i<len(tuple_ok);i++{tuple_ok[i]=0xff}

    sip.fragmentBuffer = common.NewCacheWithRemovalListener(
        /* buffer time for fragmented udp packets. */ 7000,
        /* buffer size for fragmented udp packets. */ 1000,
        func(k common.Key, v common.Value) {    // callback function when remove buffer.
            return
        })
    sip.fragmentBuffer.StartJanitor(7000)

    // before status check
    assert.Equal(t, 0 , sip.fragmentBuffer.Size() , "There should be empty." )

    // add the tuple
    sip.addBuffer(tuple_ok,&buf)
    // check after status
    assert.Equal(t, 1 , sip.fragmentBuffer.Size() , "There should be one element." )

    // unexist key case, must be nil and shuld not be change buffer size.
    buf_p_nil:=sip.deleteBuffer(tuple_ng)
    assert.Nil(t, buf_p_nil  , "There should be nil." )
    assert.Equal(t, 1 , sip.fragmentBuffer.Size() , "There should not change." )
    
    // exist key case
    buf_p:=sip.deleteBuffer(tuple_ok)
    assert.Equal(t, &buf , buf_p                  , "There should be same address." )
    assert.Equal(t, 0 , sip.fragmentBuffer.Size() , "There should be same tuple." )

}

func TestExpireBuffer(t *testing.T) {// (t *sipBuffer) {
    var msg_p *sipMessage
    sip:=sipPlugin{}

    buf:=sipBuffer{transport: transportUDP}
    _ = sip

    /*** Missing header start case : message should reject ***/
    bufferTimeout.Set(int64(0))
    messageIgnored.Set(int64(0))
    ignored_msg:=sipMessage{hdr_start: -1,hdr_len: -1,contentlength: -1}
    buf.message = &ignored_msg
    // initialized check
    assert.Equal(t, int64(0) , bufferTimeout.Get() , "The counter should be initialized with zeros." )
    assert.Equal(t, int64(0) , messageIgnored.Get() , "The counter should be initialized with zeros." )
    msg_p=sip.expireBuffer(&buf)
    // counter values check
    assert.Equal(t, int64(0) , bufferTimeout.Get() , "The counter should not be changed." )
    assert.Equal(t, int64(1) , messageIgnored.Get() , "The counter should be increased by one." )
    // nil return check
    assert.Equal(t, (*sipMessage)(nil) , msg_p , "The counter should be increased by one." )

    /*** Header incomplete case ***/
    hdr_incomplete_msg:=sipMessage{hdr_start: 0,hdr_len: -1,contentlength: -1}
    bufferTimeout.Set(int64(0))
    messageIgnored.Set(int64(0))
    buf.message = &hdr_incomplete_msg
    // initialized check
    assert.Equal(t, int64(0) , bufferTimeout.Get() , "The counter should be initialized with zeros." )
    assert.Equal(t, int64(0) , messageIgnored.Get() , "The counter should be initialized with zeros." )
    msg_p=sip.expireBuffer(&buf)
    // counter values check
    assert.Equal(t, int64(1) , bufferTimeout.Get() , "The counter should be increased by one." )
    assert.Equal(t, int64(0) , messageIgnored.Get() , "The counter should not be changed." )
    // note value check
    assert.Contains(t,msg_p.notes ,common.NetString("Buffer timeout: Could not reveive all messages.")  ,"There should be contained." )
    // returned message pointer check
    assert.Equal(t, &hdr_incomplete_msg , msg_p , "The counter should be increased by one." )

    /*** Body incomplete case ***/
    bdy_incomplete_msg:=sipMessage{hdr_start: 0,hdr_len: 20,contentlength: -1}
    bufferTimeout.Set(int64(0))
    messageIgnored.Set(int64(0))
    buf.message = &bdy_incomplete_msg
    // initialized check
    assert.Equal(t, int64(0) , bufferTimeout.Get() , "The counter should be initialized with zeros." )
    assert.Equal(t, int64(0) , messageIgnored.Get() , "The counter should be initialized with zeros." )
    msg_p=sip.expireBuffer(&buf)
    // counter values check
    assert.Equal(t, int64(1) , bufferTimeout.Get() , "The counter should be increased by one." )
    assert.Equal(t, int64(0) , messageIgnored.Get() , "The counter should not be changed." )
    // note value check
    assert.Contains(t,msg_p.notes ,common.NetString("Buffer timeout: Could not reveive all content length.") ,"There should be contained." )
    // returned message pointer check
    assert.Equal(t, &bdy_incomplete_msg , msg_p , "The counter should be increased by one." )
}

func TestConnectionTimeout(t *testing.T) {// () time.Duration {
    sip:=sipPlugin{}
    sip.fragmentBufferTimeout=999

    assert.Equal(t, int(999), int(sip.ConnectionTimeout()) , "sip.fragmentBufferTimeout and ConnectionTimeout() should be same." )
}

func TestPublishMessage(t *testing.T) {// (msg *sipMessage) {
    sip:=sipPlugin{}
    ipTuple := common.NewIPPortTuple(4,
        net.ParseIP("10.0.0.1"), 1111,
        net.ParseIP("10.0.0.2"), 2222)
    msg:=sipMessage{transport:0, raw:common.NetString("test raw string"),
                    tuple: ipTuple , method: common.NetString("INVITE") ,
                    requestUri: common.NetString("sip:test"),
                    statusCode: uint16(200), statusPhrase: common.NetString("OK"),
                    from: common.NetString("from"), to: common.NetString("to"),
                    cseq: common.NetString("cseq"), callid: common.NetString("callid"),
                    contentlength: 10}

    // avoid to sip.results initialization error
    sip.publishMessage(&msg)
    assert.Nil(t, sip.results , "sip.results should still nil." )

    // 
    event:= &eventStore{}
    //callback:= func(beat.Event){}
    sip.results=event.publish
    sip.publishMessage(&msg)
    fmt.Printf("%s\n",event)
}

func TestSipTupleFromIPPort(t *testing.T) {// (t *common.IPPortTuple, trans transport) sipTuple {
}

func TestCreateSIPMessage(t *testing.T) {// (transp transport, rawData []byte) (msg *sipMessage, err error) {
}

func TestNewBuffer(t *testing.T) {// (ts time.Time, tuple sipTuple, cmd common.CmdlineTuple,msg *sipMessage) *sipBuffer {
}

func TestParseUDP(t *testing.T) {// (pkt *protos.Packet) {
}

