
package main

import "encoding/binary"

const NetMessageHeadSize = 4 * 4 + 8
const NetMessageBodySize = 1 << 10
const NetReceiveBufferSize = NetMessageHeadSize + NetMessageBodySize

type Message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    body [NetMessageBodySize]byte
}

func (message *Message) pack() []byte {
    bytes := make([]byte, NetReceiveBufferSize)
    const intSize = 4
    const longSize = 8

    flagBytes := make([]byte, intSize)
    binary.LittleEndian.PutUint32(flagBytes, uint32(message.flag))
    for index, item := range flagBytes { bytes[index] = item }

    timestampBytes := make([]byte, longSize)
    binary.LittleEndian.PutUint64(timestampBytes, message.timestamp)
    for index, item := range timestampBytes { bytes[index + intSize] = item }

    sizeBytes := make([]byte, intSize)
    binary.LittleEndian.PutUint32(sizeBytes, message.size)
    for index, item := range sizeBytes { bytes[index + intSize + longSize] = item }

    indexBytes := make([]byte, intSize)
    binary.LittleEndian.PutUint32(indexBytes, message.size)
    for index, item := range indexBytes { bytes[index + intSize * 2 + longSize] = item }

    countBytes := make([]byte, intSize)
    binary.LittleEndian.PutUint32(countBytes, message.size)
    for index, item := range countBytes { bytes[index + intSize * 3 + longSize] = item }

    for index, item := range message.body { bytes[index + NetMessageHeadSize] = item }

    return bytes
}

func unpackMessage(bytes []byte) *Message {

    return nil
}
