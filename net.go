
package main

import "unsafe"

const _MessageHeadSize = 4 * 4 + 8 // 24
const _MessageBodySize = 1 << 10 // 1024
const _MessageSize = _MessageHeadSize + _MessageBodySize // 1048
const _IntSize = 4 // Gimme the private (file-scope) modifier, ASAP!
const _LongSize = 8 // At least the private modifier as I need the protected and package-private/internal modifiers too

type Message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    body [_MessageBodySize]byte
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (message *Message) _pack() []byte {
    bytes := make([]byte, _MessageSize)

    copy(unsafe.Slice(&(bytes[0]), _IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), _IntSize))
    copy(unsafe.Slice(&(bytes[_IntSize]), _LongSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), _LongSize))
    copy(unsafe.Slice(&(bytes[_IntSize+_LongSize]), _IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), _IntSize))
    copy(unsafe.Slice(&(bytes[_IntSize* 2 +_LongSize]), _IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), _IntSize))
    copy(unsafe.Slice(&(bytes[_IntSize* 3 +_LongSize]), _IntSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), _IntSize))

    copy(unsafe.Slice(&(bytes[_MessageHeadSize]), _MessageBodySize), unsafe.Slice(&(message.body[0]), _MessageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func _unpackMessage(bytes []byte) *Message {
    message := new(Message)

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), _IntSize), unsafe.Slice(&(bytes[0]), _IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), _LongSize), unsafe.Slice(&(bytes[_IntSize]), _LongSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), _IntSize), unsafe.Slice(&(bytes[_IntSize+_LongSize]), _IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), _IntSize), unsafe.Slice(&(bytes[_IntSize* 2 +_LongSize]), _IntSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), _IntSize), unsafe.Slice(&(bytes[_IntSize* 3 +_LongSize]), _IntSize))

    copy(unsafe.Slice(&(message.body[0]), _MessageBodySize), unsafe.Slice(&(bytes[_MessageHeadSize]), _MessageBodySize))
    return message
}
