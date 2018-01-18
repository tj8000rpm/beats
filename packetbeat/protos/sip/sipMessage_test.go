package sip

import (
    "testing"
    "fmt"

    "github.com/stretchr/testify/assert"

    "github.com/elastic/beats/libbeat/common"
)

func TestSeparatedStrings(t *testing.T) {
    msg := sipMessage{}
    var input_str string
    var separatedStrings *[]common.NetString

    input_str = "aaaa,bbbb,cccc,dddd"
    separatedStrings = msg.separateCsv(input_str)
    assert.Equal(t, "aaaa", fmt.Sprintf("%s",(*separatedStrings)[0]), "There should be [aaaa].")
    assert.Equal(t, "bbbb", fmt.Sprintf("%s",(*separatedStrings)[1]), "There should be [bbbb].")
    assert.Equal(t, "cccc", fmt.Sprintf("%s",(*separatedStrings)[2]), "There should be [cccc].")
    assert.Equal(t, "dddd", fmt.Sprintf("%s",(*separatedStrings)[3]), "There should be [dddd].")

    input_str = ",aaaa,\"bbbb,ccc\",dddd\\,eeee,\\\"ff,gg\\\","
    separatedStrings = msg.separateCsv(input_str)
    assert.Equal(t, ""            , fmt.Sprintf("%s",(*separatedStrings)[0]), "There should be blank.")
    assert.Equal(t, "aaaa"        , fmt.Sprintf("%s",(*separatedStrings)[1]), "There should be [aaaa].")
    assert.Equal(t, "\"bbbb,ccc\"", fmt.Sprintf("%s",(*separatedStrings)[2]), "There should be [\"bbbb,ccc\"].")
    assert.Equal(t, "dddd\\,eeee" , fmt.Sprintf("%s",(*separatedStrings)[3]), "There should be [dddd\\,eeee].")
    assert.Equal(t, "\\\"ff"      , fmt.Sprintf("%s",(*separatedStrings)[4]), "There should be [\\\"ff].")
    assert.Equal(t, "gg\\\""      , fmt.Sprintf("%s",(*separatedStrings)[5]), "There should be [gg\\\"].")
    assert.Equal(t, ""            , fmt.Sprintf("%s",(*separatedStrings)[6]), "There should be blank.")

    input_str = "aaaa,\"aaaaa,bbb"
    separatedStrings = msg.separateCsv(input_str)
    assert.Equal(t,"aaaa"       , fmt.Sprintf("%s",(*separatedStrings)[0]), "There should be [aaaa].")
    assert.Equal(t,"\"aaaaa,bbb", fmt.Sprintf("%s",(*separatedStrings)[1]), "There should be [\"aaaaa,bbb].")

    input_str = "aaaa,\"aaaaa,"
    separatedStrings = msg.separateCsv(input_str)
    assert.Equal(t,"aaaa"    , fmt.Sprintf("%s",(*separatedStrings)[0]), "There should be [aaaa].")
    assert.Equal(t,"\"aaaaa,", fmt.Sprintf("%s",(*separatedStrings)[1]), "There should be [\"aaaaa,].")
}

// func TestParseSIPHeader() // (err error){
// func TestParseSIPHeaderToMap(cutPosS []int,cutPosE []int)// (*map[string][]common.NetString,[]string) {
// func TestParseSIPBody()// (err error){
func TestParseBody_SDP(t *testing.T) {
    var result  *map[string][]common.NetString
    var err     error
    var garbage []byte

    msg := sipMessage{}

    // nil
    result,err =msg.parseBody_SDP(garbage)
    assert.Equal(t,nil                    , err                                 , "error recived"    )
    assert.Equal(t,0                      , len(*result)                        , "There should be." )

    // malformed
    garbage = []byte( "\r\n123149afajbngohk;kdgj\r\najkavnaa:aaaa\r\n===a===")
    result,err =msg.parseBody_SDP(garbage)
    assert.Equal(t,nil                    , err                                 , "error recived"    )
    assert.Equal(t,1                      , len(*result)                        , "There should be." )
    assert.Equal(t,"==a==="               , fmt.Sprintf("%s",(*result)[""][0])  , "There should be." )

    garbage = []byte( "v=0\r\n"                         +
                      "o=- 0 0 IN IP4 10.0.0.1    \r\n" + // Trim spaces
                      "s=-\r\n"                         +
                      "c=IN IP4 10.0.0.1\r\n"           +
                      "t=0 0\r\n"                       +
                      "m=audio 5012 RTP/AVP 0 16\r\n"   +
                      "a=rtpmap:0 PCMU/8000\r\n"        + // Multiple
                      "a=rtpmap:16 G729/8000\r\n")

    result,err =msg.parseBody_SDP(garbage)
    assert.Equal(t,nil                    , err                                 , "error recived"    )

    assert.Equal(t,7                      , len(*result)                        , "There should be." )
    assert.Equal(t,1                      , len((*result)["v"])                 , "There should be." )
    assert.Equal(t,1                      , len((*result)["o"])                 , "There should be." )
    assert.Equal(t,1                      , len((*result)["c"])                 , "There should be." )
    assert.Equal(t,1                      , len((*result)["t"])                 , "There should be." )
    assert.Equal(t,2                      , len((*result)["a"])                 , "There should be." )
    assert.Equal(t,"0"                    , fmt.Sprintf("%s",(*result)["v"][0]) , "There should be." )
    assert.Equal(t,"- 0 0 IN IP4 10.0.0.1", fmt.Sprintf("%s",(*result)["o"][0]) , "There should be." )
    assert.Equal(t,"IN IP4 10.0.0.1"      , fmt.Sprintf("%s",(*result)["c"][0]) , "There should be." )
    assert.Equal(t,"0 0"                  , fmt.Sprintf("%s",(*result)["t"][0]) , "There should be." )
    assert.Equal(t,"rtpmap:0 PCMU/8000"   , fmt.Sprintf("%s",(*result)["a"][0]) , "There should be." )
    assert.Equal(t,"rtpmap:16 G729/8000"  , fmt.Sprintf("%s",(*result)["a"][1]) , "There should be." )

}
