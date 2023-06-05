
package main

import "unsafe"

const MessageHeadSize = 4 * 4 + 8 // 24
const MessageBodySize = 1 << 10 // 1024
const MessageSize = MessageHeadSize + MessageBodySize // 1048
const IntSize = 4 // Gimme the private (file-scope) modifier, ASAP!
const LongSize = 8 // At least the private modifier as I need the protected and package-private/internal modifiers too

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

    copy(unsafe.Slice(&(bytes[0]), IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), IntSize))
    copy(unsafe.Slice(&(bytes[IntSize]), LongSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), LongSize))
    copy(unsafe.Slice(&(bytes[IntSize+LongSize]), IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), IntSize))
    copy(unsafe.Slice(&(bytes[IntSize* 2 +LongSize]), IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), IntSize))
    copy(unsafe.Slice(&(bytes[IntSize* 3 +LongSize]), IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), IntSize))

    copy(unsafe.Slice(&(bytes[MessageHeadSize]), MessageBodySize), unsafe.Slice(&(message.body[0]), MessageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte)
func unpackMessage(bytes []byte) *Message {
    message := new(Message) // TODO: generics

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), IntSize), unsafe.Slice(&(bytes[0]), IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), LongSize), unsafe.Slice(&(bytes[IntSize]), LongSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), IntSize), unsafe.Slice(&(bytes[IntSize+LongSize]), IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), IntSize), unsafe.Slice(&(bytes[IntSize* 2 +LongSize]), IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), IntSize), unsafe.Slice(&(bytes[IntSize* 3 +LongSize]), IntSize))

    copy(unsafe.Slice(&(message.body[0]), MessageBodySize), unsafe.Slice(&(bytes[MessageHeadSize]), MessageBodySize))
    return message
}
