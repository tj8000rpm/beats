package sip

import (
    "testing"
    "net"

    "github.com/stretchr/testify/assert"
)


func TestComputeHashebles(t *testing.T) {
    tuple := sipTuple{}
    for i:=0;i<maxHashableSipTupleRawSize;i++{
        assert.Equal(t, byte(0x00),tuple.raw[i], "There should be zero initialized.")
    }

    tuple.ipLength=4
    tuple.SrcIP=net.ParseIP("10.1.2.3")
    tuple.SrcPort=5060
    tuple.DstIP=net.ParseIP("fe:aa:cc:22::55:11")
    tuple.DstPort=5060
    tuple.transport=transportUDP

    tuple.computeHashebles()

    assert.Equal(t, ([]byte)(net.ParseIP("10.1.2.3"))          ,tuple.raw[ 0:16], "There should be [ip v4 10.1.2.3].")
    assert.Equal(t, ([]byte{0x13,0xc4})                        ,tuple.raw[16:18], "There should be [src port 5060].")
    assert.Equal(t, ([]byte)(net.ParseIP("fe:aa:cc:22::55:11")),tuple.raw[18:34], "There should be [ip v6 fe:aa:cc:22::55:11].")
    assert.Equal(t, ([]byte{0x13,0xc4})                        ,tuple.raw[34:36], "There should be [dst port 5060].")
    assert.Equal(t, ([]byte{0x01})                             ,tuple.raw[36:  ], "There should be [transport udp].")
}

func TestString(t *testing.T) {
    tuple := sipTuple{}

    tuple.ipLength=4
    tuple.SrcIP=net.ParseIP("10.1.2.3")
    tuple.SrcPort=5060
    tuple.DstIP=net.ParseIP("fe:aa:cc:22::55:11")
    tuple.DstPort=5060
    tuple.transport=1

    assert.Equal(t, "sipTuple Src[10.1.2.3:5060] Dst[fe:aa:cc:22::55:11:5060] transport[udp]" ,tuple.String(), "Invalid fromat or values.")
}

func TestHashable(t *testing.T){
    tuple := sipTuple{}
    for i:=0;i<maxHashableSipTupleRawSize;i++{
        assert.Equal(t, byte(0x00),tuple.raw[i], "There should be zero initialized.")
    }

    tuple.ipLength=4
    tuple.SrcIP=net.ParseIP("10.1.2.3")
    tuple.SrcPort=5060
    tuple.DstIP=net.ParseIP("fe:aa:cc:22::55:11")
    tuple.DstPort=5060
    tuple.transport=transportUDP

    tuple.computeHashebles()
    hash:=tuple.hashable()

    assert.Equal(t, ([]byte)(net.ParseIP("10.1.2.3"))          ,hash[ 0:16], "There should be [ip v4 10.1.2.3].")
    assert.Equal(t, ([]byte{0x13,0xc4})                        ,hash[16:18], "There should be [src port 5060].")
    assert.Equal(t, ([]byte)(net.ParseIP("fe:aa:cc:22::55:11")),hash[18:34], "There should be [ip v6 fe:aa:cc:22::55:11].")
    assert.Equal(t, ([]byte{0x13,0xc4})                        ,hash[34:36], "There should be [dst port 5060].")
    assert.Equal(t, ([]byte{0x01})                             ,hash[36:  ], "There should be [transport udp].")
}
