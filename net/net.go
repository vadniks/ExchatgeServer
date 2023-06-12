
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/utils"
    "fmt"
    goNet "net"
    "sync"
    "sync/atomic"
    "unsafe"
)

const host = "localhost:8080"

const paddingBlockSize = 16

const messageHeadSize = 4 * 6 + 8 // 32
const messageBodySize = 1 << 10 // 1024
const messageSize = messageHeadSize + messageBodySize // 1056

const intSize = 4
const longSize = 8

const flagFinish = 0xffffffff
const flagUnauthenticated = 0x7ffffffe
const flagAdminShutdown = 0x00000000

const clientMessageFinish = 1
const clientMessageProceed = 0
const clientMessageShutdown = -1

type net struct {
    serverKeys *crypto.KeyPair
    messageBufferSize uint
}
var this *net

type message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    from uint32
    to uint32
    body [messageBodySize]byte // TODO: generate permanent encryption key for each conversation and store encrypted messages in a database
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (message *message) pack() []byte {
    bytes := make([]byte, messageSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize))
    copy(unsafe.Slice(&(bytes[intSize + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.from))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(message.to))), intSize))

    copy(unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize), unsafe.Slice(&(message.body[0]), messageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func unpackMessage(bytes []byte) *message {
    message := new(message) // TODO: make generic lambda to copy bytes

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize), unsafe.Slice(&(bytes[0]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize), unsafe.Slice(&(bytes[intSize]), longSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize), unsafe.Slice(&(bytes[intSize + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize), unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize), unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.from))), intSize), unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.to))), intSize), unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize))

    copy(unsafe.Slice(&(message.body[0]), messageBodySize), unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize))
    return message
}

func Initialize() {
    var byteOrderChecker uint64 = 0x0123456789abcdef // only on x64 littleEndian data marshalling will work as clients expect
    utils.Assert(*((*uint8) (unsafe.Pointer(&byteOrderChecker))) == 0xef)

    this = &net{serverKeys: crypto.GenerateServerKeys()}
    crypto.Initialize(this.serverKeys, paddingBlockSize, messageSize)
    this.messageBufferSize = crypto.EncryptedSize()
}

func ProcessClients() {
    listener, err := goNet.Listen("tcp", host)
    utils.Assert(err == nil)

    var waitGroup sync.WaitGroup

    var acceptingClients atomic.Bool
    acceptingClients.Store(true)

    onShutDownRequested := func() {
        acceptingClients.Store(false)
        utils.Assert(listener.Close() == nil)
        waitGroup.Wait()
    }

    for acceptingClients.Load() {
        connection, err := listener.Accept()
        if err != nil { break }

        waitGroup.Add(1)
        go processClient(&connection, &waitGroup, &onShutDownRequested)
    }
}

func processClient(connection *goNet.Conn, waitGroup *sync.WaitGroup, onShutDownRequested *func()) {
    send(connection, this.serverKeys.PublicKey())

    clientPublicKey := make([]byte, crypto.PublicKeySize)
    receive(connection, clientPublicKey)
    sessionKeys := crypto.GenerateSessionKeys(clientPublicKey)

    messageBuffer := make([]byte, this.messageBufferSize)
    for {
        if receive(connection, messageBuffer) {
            switch processClientMessage(connection, sessionKeys, messageBuffer) {
                case clientMessageFinish:
                    waitGroup.Done()
                    return
                case clientMessageProceed:
                    break
                case clientMessageShutdown:
                    waitGroup.Done()
                    (*onShutDownRequested)()// TODO: verify client's administrative rights to allow requesting shutdown
                    return
            }
        }
    }
}

func send(connection *goNet.Conn, payload []byte) {
    count, err := (*connection).Write(payload)
    utils.Assert(count == len(payload) && err == nil)
}

func receive(connection *goNet.Conn, buffer []byte) bool {
    count, err := (*connection).Read(buffer)
    utils.Assert(err == nil)
    return count == len(buffer)
}

var testCount = 0 // TODO: test only
func processClientMessage(connection *goNet.Conn, sessionKeys *crypto.KeyPair, messageBytes []byte) int {
    if testCount > 0 { // TODO: test only
        decrypted := crypto.Decrypt(sessionKeys, messageBytes)
        test := unpackMessage(decrypted) // TODO: test only
        fmt.Println("#####",
            test.flag,
            test.timestamp,
            test.size,
            test.index,
            test.count,
            test.from,
            test.to,
            string(test.body[:]),
        )

        return clientMessageShutdown
    }
    testCount++

    decrypted := crypto.Decrypt(sessionKeys, messageBytes)
    test := unpackMessage(decrypted) // TODO: test only
    fmt.Println(
        "@@@@@",
        test.flag,
        test.timestamp,
        test.size,
        test.index,
        test.count,
        test.from,
        test.to,
    )

    test2 := &message{ // TODO: test only
        int32(0x12345678),
        0,
        1,
        0,
        1,
        255,
        255,
        [messageBodySize]byte{},
    }
    for i, _ := range test2.body { test2.body[i] = 'a' }
    send(connection, crypto.Encrypt(sessionKeys, test2.pack()))

    return clientMessageProceed
}
