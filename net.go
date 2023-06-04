
package main

import (
    "encoding/binary"
    "reflect"
    "unsafe"
)

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

func putUint32(b *[]byte, v uint32) {
    bb := (*[unsafe.Sizeof(v)]byte)(unsafe.Pointer(b))
    (*bb)[0] = byte(v)
    (*bb)[1] = byte(v >> 8)
    (*bb)[2] = byte(v >> 16)
    (*bb)[3] = byte(v >> 24)
}

func putUint64(b *[]byte, v uint64) {
    bb := (*[unsafe.Sizeof(v)]byte)(unsafe.Pointer(b))
    (*bb)[0] = byte(v)
    (*bb)[1] = byte(v >> 8)
    (*bb)[2] = byte(v >> 16)
    (*bb)[3] = byte(v >> 24)
    (*bb)[4] = byte(v >> 32)
    (*bb)[5] = byte(v >> 40)
    (*bb)[6] = byte(v >> 48)
    (*bb)[7] = byte(v >> 56)
}

func getUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func getUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func (message *Message) pack() []byte {
    bytes := make([]byte, MessageSize)
    reflectValue := reflect.ValueOf(bytes)

    getBufferSegment := func(offset uint) *[]byte {
        return (*[]byte) (unsafe.Add(unsafe.Pointer(reflectValue.Pointer()), offset))
    }

    putUint32(getBufferSegment(0), uint32(message.flag))
    putUint64(getBufferSegment(intSize), message.timestamp)
    putUint32(getBufferSegment(intSize + longSize), message.size)
    putUint32(getBufferSegment(intSize * 2 + longSize), message.index)
    putUint32(getBufferSegment(intSize * 3 + longSize), message.count)

    copy(unsafe.Slice(&bytes[MessageHeadSize], MessageBodySize), unsafe.Slice(&(message.body[0]), MessageBodySize))

    return bytes
}

func unpackMessage(bytes []byte) *Message {
    message := &Message{
        int32(getUint32(bytes[:intSize])),
        getUint64(bytes[intSize:longSize + intSize]),
        getUint32(bytes[intSize + longSize:intSize * 2 + longSize]),
        getUint32(bytes[intSize * 2 + longSize:intSize * 3 + longSize]),
        getUint32(bytes[intSize * 3 + longSize:MessageHeadSize]),
        [MessageBodySize]byte{},
    }

    copy(unsafe.Slice(&(message.body[0]), MessageBodySize), unsafe.Slice(&bytes[MessageHeadSize], MessageBodySize))
    return message
}
