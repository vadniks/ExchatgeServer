
package main

import "encoding/binary"

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

func putUint32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func putUint64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
func getUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func getUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func (message *Message) pack() []byte { // TODO: write all ints/longs directly in bytes buffer without creating separate buffers for each using unsafe package
    bytes := make([]byte, MessageSize)

    flagBytes := make([]byte, intSize)
    putUint32(flagBytes, uint32(message.flag))
    for index, item := range flagBytes { bytes[index] = item }

    timestampBytes := make([]byte, longSize)
    putUint64(timestampBytes, message.timestamp)
    for index, item := range timestampBytes { bytes[index + intSize] = item }

    sizeBytes := make([]byte, intSize)
    putUint32(sizeBytes, message.size)
    for index, item := range sizeBytes { bytes[index + intSize + longSize] = item }

    indexBytes := make([]byte, intSize)
    putUint32(indexBytes, message.index)
    for index, item := range indexBytes { bytes[index + intSize * 2 + longSize] = item }

    countBytes := make([]byte, intSize)
    putUint32(countBytes, message.count)
    for index, item := range countBytes { bytes[index + intSize * 3 + longSize] = item }

    for index, item := range message.body { bytes[index + MessageHeadSize] = item }

    return bytes
}

func unpackMessage(bytes []byte) *Message {
    msg := &Message{
        int32(getUint32(bytes[:intSize])),
        getUint64(bytes[intSize:longSize + intSize]),
        getUint32(bytes[intSize + longSize:intSize * 2 + longSize]),
        getUint32(bytes[intSize * 2 + longSize:intSize * 3 + longSize]),
        getUint32(bytes[intSize * 3 + longSize:MessageHeadSize]),
        [MessageBodySize]byte{},
    }

    for index, item := range bytes[MessageHeadSize:] { msg.body[index] = item }
    return msg
}
