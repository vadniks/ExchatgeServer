
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/utils"
    "github.com/jamesruan/sodium"
    goNet "net"
    "sync"
    "sync/atomic"
    "unsafe"
)

const host = "localhost:8080"

const intSize = 4
const longSize = 8

const messageSize uint = 1 << 10 // exactly 1 kB
const tokenTrailingSize uint = 16
const tokenUnencryptedValueSize = 2 * intSize // 8
const tokenSize = tokenUnencryptedValueSize + 40 + tokenTrailingSize // 48 + 16 = 64 = 2 encrypted ints + mac + nonce + missing bytes to reach signatureSize so the server can tokenize itself via signature whereas for clients server encrypts 2 ints (connectionId, userId)
const messageHeadSize = intSize * 6 + longSize + tokenSize // 96
const messageBodySize = messageSize - messageHeadSize // 928

type net struct {
    serverPublicKey []byte
    serverSecretKey []byte
    messageBufferSize uint
}
var this *net = nil

type message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    from uint32
    to uint32
    token [tokenSize]byte // TODO: generate server token for each connection
    body [messageBodySize]byte // TODO: generate permanent encryption key for each conversation and store encrypted messages in a database
}

var connections = make(map[uint32]*goNet.Conn) // key is connectionId
var encryptionKeys = make(map[uint32][]byte) // key is connectionId

var tokenEncryptionKey = func() []byte {
    key := new(sodium.SecretBoxKey)
    sodium.Randomize(key)
    utils.Assert(len(key.Bytes) == int(crypto.KeySize))
    return key.Bytes
}()

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (msg *message) pack() []byte {
    utils.Assert(msg != nil)
    bytes := make([]byte, messageSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.flag))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.timestamp))), longSize))
    copy(unsafe.Slice(&(bytes[intSize + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.size))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.index))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.count))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.from))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.to))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 6 + longSize]), tokenSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.token))), tokenSize))

    copy(unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize), unsafe.Slice(&(msg.body[0]), messageBodySize))
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func unpackMessage(bytes []byte) *message {
    utils.Assert(len(bytes) > 0)
    message := new(message) // TODO: make generic lambda to copy bytes

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.flag))), intSize), unsafe.Slice(&(bytes[0]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.timestamp))), longSize), unsafe.Slice(&(bytes[intSize]), longSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.size))), intSize), unsafe.Slice(&(bytes[intSize + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.index))), intSize), unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.count))), intSize), unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.from))), intSize), unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.to))), intSize), unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.token))), tokenSize), unsafe.Slice(&(bytes[intSize * 6 + longSize]), tokenSize))

    copy(unsafe.Slice(&(message.body[0]), messageBodySize), unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize))
    return message
}

//goland:noinspection GoRedundantConversion for (*byte) as without this it won't compile
func makeToken(connectionId uint32, userId uint32) [tokenSize]byte {
    bytes := make([]byte, tokenUnencryptedValueSize)

    copy(bytes, unsafe.Slice((*byte) (unsafe.Pointer(&connectionId)), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&userId)), intSize))

    encrypted := crypto.Encrypt(bytes, tokenEncryptionKey)
    utils.Assert(len(encrypted) == int(tokenSize - tokenTrailingSize))

    withTrailing := [tokenSize]byte{}
    copy(unsafe.Slice(&(withTrailing[0]), tokenSize), encrypted)

    return withTrailing
}

//goland:noinspection GoRedundantConversion for (*byte) as without this it won't compile
func openToken(withTrailing [tokenSize]byte) (*uint32, *uint32) { // nillable results
    token := withTrailing[:tokenSize - tokenTrailingSize]
    utils.Assert(len(token) == int(crypto.EncryptedSize(tokenUnencryptedValueSize)))

    decrypted := crypto.Decrypt(token, tokenEncryptionKey)
    if decrypted == nil || len(decrypted) != tokenUnencryptedValueSize { return nil, nil }

    connectionId := new(uint32); userId := new(uint32)
    copy(unsafe.Slice((*byte) (unsafe.Pointer(connectionId)), intSize), decrypted)
    copy(unsafe.Slice((*byte) (unsafe.Pointer(userId)), intSize), unsafe.Slice(&(decrypted[intSize]), intSize))

    return connectionId, userId
}

func Initialize() {
    var byteOrderChecker uint64 = 0x0123456789abcdef // only on x64 littleEndian data marshalling will work as clients expect
    utils.Assert(unsafe.Sizeof(uintptr(0)) == 8 && *((*uint8) (unsafe.Pointer(&byteOrderChecker))) == 0xef)

    serverPublicKey, serverSecretKey := crypto.GenerateServerKeys()

    this = &net{
       serverPublicKey,
       serverSecretKey,
       crypto.EncryptedSize(messageSize),
    }
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

    var connectionId uint32 = 0 // TODO: limit connections count to [0, 0x7ffffffe] as service flags are above
    for acceptingClients.Load() {
        connection, err := listener.Accept()
        if err != nil { break }

        waitGroup.Add(1)
        connections[connectionId] = &connection
        go processClient(connectionId, &waitGroup, &onShutDownRequested)
        connectionId++
    }
}

func processClient(connectionId uint32, waitGroup *sync.WaitGroup, onShutDownRequested *func()) {
    utils.Assert(waitGroup != nil && onShutDownRequested != nil)
    connection := connections[connectionId]

    closeConnection := func() {
        delete(connections, connectionId)
        waitGroup.Done()
        utils.Assert((*connection).Close() == nil)
    }

    send(connection, crypto.Sign(this.serverPublicKey))

    clientPublicKey := make([]byte, crypto.KeySize)
    receive(connection, clientPublicKey, nil)

    encryptionKey := crypto.ExchangeKeys(this.serverPublicKey, this.serverSecretKey, clientPublicKey)
    if encryptionKey == nil {
        closeConnection()
        return
    }
    encryptionKeys[connectionId] = encryptionKey

    messageBuffer := make([]byte, this.messageBufferSize)
    for {
        disconnected := false

        if receive(connection, messageBuffer, &disconnected) { // TODO: add timeout for an opened connection and limit connection count
            switch processClientMessage(connectionId, messageBuffer) {
                case flagFinishToReconnect: fallthrough // --& --x-- falling through until I decide what to do with them
                case flagFinishWithError: fallthrough
                case flagFinish:
                    closeConnection()
                    return
                case flagShutdown:
                    closeConnection()
                    (*onShutDownRequested)()
                    return
                case flagProceed: fallthrough // --x--
                case flagError: fallthrough
                case flagSuccess: func(){}()
            }
        }

        if disconnected {
            closeConnection()
            return
        }
    }
}

func send(connection *goNet.Conn, payload []byte) {
    utils.Assert(connection != nil && len(payload) > 0)
    count, err := (*connection).Write(payload)
    utils.Assert(count == len(payload) && err == nil)
}

func receive(connection *goNet.Conn, buffer []byte, /*nillable*/ error *bool) bool {
    utils.Assert(connection != nil && len(buffer) > 0)

    count, err := (*connection).Read(buffer)
    if error != nil { *error = err != nil }
    if err != nil { return false }

    return count == len(buffer)
}

func processClientMessage(connectionId uint32, messageBytes []byte) int32 {
    encryptionKey := encryptionKeys[connectionId]
    utils.Assert(len(encryptionKey) > 0 && len(messageBytes) > 0)

    decrypted := crypto.Decrypt(messageBytes, encryptionKey)
    message := unpackMessage(decrypted)

    return routeMessage(connectionId, message)
}

func sendMessage(connectionId uint32, msg *message) {
    encryptionKey := encryptionKeys[connectionId]
    utils.Assert(msg != nil && len(encryptionKey) > 0)

    connection := connections[connectionId]
    utils.Assert(connection != nil)

    packed := msg.pack()
    encrypted := crypto.Encrypt(packed, encryptionKey)

    send(connection, encrypted)
}
