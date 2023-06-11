
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/utils"
    "unsafe"
    goNet "net"
)

const host = "localhost:8080"
const paddingBlockSize = 16
const messageHeadSize = 4 * 4 + 8 // 24
const messageBodySize = 1 << 10 // 1024
const messageSize = messageHeadSize + messageBodySize // 1048
const intSize = 4
const longSize = 8
var this *net

type net struct {
    serverKeys *crypto.KeyPair
}

type message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    body [messageBodySize]byte
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (message *message) pack() []byte {
    bytes := make([]byte, messageSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize))
    copy(unsafe.Slice(&(bytes[intSize + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize))

    copy(unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize), unsafe.Slice(&(message.body[0]), messageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func unpackMessage(bytes []byte) *message {
    message := new(message)

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize), unsafe.Slice(&(bytes[0]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize), unsafe.Slice(&(bytes[intSize]), longSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize), unsafe.Slice(&(bytes[intSize + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize), unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize), unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize))

    copy(unsafe.Slice(&(message.body[0]), messageBodySize), unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize))
    return message
}

func Initialize() {
    this = &net{serverKeys: crypto.GenerateServerKeys()}
    crypto.Initialize(this.serverKeys, paddingBlockSize, messageSize)
}

func ProcessClients() {
    server, err := goNet.Listen("tcp", host)
    utils.Assert(err == nil)
    defer utils.Assert(server.Close() == nil)

    for {
        // TODO
    }
}

func processClient() {
    clientPublicKeyBuffer := make([]byte, crypto.PublicKeySize)
    clientPublicKeyBuffer[0] = 0 // TODO

    sessionKeys := crypto.GenerateSessionKeys(clientPublicKeyBuffer)
    a := sessionKeys.Key1 // TODO
    a[0] = 0
}
