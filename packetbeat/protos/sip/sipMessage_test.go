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


