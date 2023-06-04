
package main

import "unsafe"

const MessageHeadSize = 4 * 4 + 8 // 24
const MessageBodySize = 1 << 10 // 1024
const MessageSize = MessageHeadSize + MessageBodySize // 1048
const ReceiveBufferSize = 1096 // TODO: encryptedSize
const intSize = 4
const longSize = 8

type Message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    body [MessageBodySize]byte
}

//goland:noinspection GoRedundantConversion (*byte)
func (message *Message) pack() []byte {
    bytes := make([]byte, MessageSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize))
    copy(unsafe.Slice(&(bytes[intSize + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize))

    copy(unsafe.Slice(&(bytes[MessageHeadSize]), MessageBodySize), unsafe.Slice(&(message.body[0]), MessageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte)
func unpackMessage(bytes []byte) *Message {
    message := &Message{}

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize), unsafe.Slice(&(bytes[0]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize), unsafe.Slice(&(bytes[intSize]), longSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize), unsafe.Slice(&(bytes[intSize + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize), unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize), unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize))

    copy(unsafe.Slice(&(message.body[0]), MessageBodySize), unsafe.Slice(&(bytes[MessageHeadSize]), MessageBodySize))
    return message
}
