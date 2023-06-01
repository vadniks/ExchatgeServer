
package main

const NetMessageHeadSize = 4 * 4 + 8
const NetMessageBodySize = 1 << 10
const NetReceiveBufferSize = NetMessageHeadSize + NetMessageBodySize

type Message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    bytes [NetMessageBodySize]byte
}

func (message Message) pack() []byte {
    return nil
}

func unpack(bytes []byte) *Message {
    return nil
}
