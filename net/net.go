
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/idsPool"
    "ExchatgeServer/utils"
    goNet "net"
    goSync "sync"
    "sync/atomic"
    "unsafe"
)

const host = "localhost:8080"

const intSize = 4
const longSize = 8

const MaxUsersCount = 100

const messageSize uint = 1 << 10 // exactly 1 kB
const messageHeadSize = intSize * 6 + longSize + crypto.TokenSize // 96
const messageBodySize = messageSize - messageHeadSize // 928
const userInfoSize = intSize + 1/*sizeof(bool)*/ + usernameSize // 21

type netT struct {
    serverPublicKey []byte
    serverSecretKey []byte
    messageBufferSize uint
    connectionIdsPool *idsPool.IdsPool
}
var net *netT = nil

type message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    from uint32
    to uint32
    token [crypto.TokenSize]byte
    body [messageBodySize]byte // TODO: generate permanent encryption key for each conversation and store encrypted messages in a database
}

type userInfo struct {
    id uint32
    connected bool
    name [usernameSize]byte
}

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
    copy(unsafe.Slice(&(bytes[intSize * 6 + longSize]), crypto.TokenSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.token))), crypto.TokenSize))

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
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(message.token))), crypto.TokenSize), unsafe.Slice(&(bytes[intSize * 6 + longSize]), crypto.TokenSize))

    copy(unsafe.Slice(&(message.body[0]), messageBodySize), unsafe.Slice(&(bytes[messageHeadSize]), messageBodySize))
    return message
}

//goland:noinspection GoRedundantConversion
func (xUserInfo *userInfo) pack() []byte {
    utils.Assert(unsafe.Sizeof(false) == 1)
    bytes := make([]byte, userInfoSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.id))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), 1), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.connected))), 1))
    copy(unsafe.Slice(&(bytes[intSize + 1]), usernameSize), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.name))), usernameSize))

    return bytes
}

func Initialize() {
    var byteOrderChecker uint64 = 0x0123456789abcdef // only on x64 littleEndian data marshalling will work as clients expect
    utils.Assert(unsafe.Sizeof(uintptr(0)) == 8 && *((*uint8) (unsafe.Pointer(&byteOrderChecker))) == 0xef)

    serverPublicKey, serverSecretKey := crypto.GenerateServerKeys()

    net = &netT{
       serverPublicKey,
       serverSecretKey,
       crypto.EncryptedSize(messageSize),
        idsPool.InitIdsPool(MaxUsersCount),
    }
}

func ProcessClients() {
    listener, err := goNet.Listen("tcp", host)
    utils.Assert(err == nil)

    var waitGroup goSync.WaitGroup

    var acceptingClients atomic.Bool
    acceptingClients.Store(true)

    onShutDownRequested := func() {
        acceptingClients.Store(false)
        utils.Assert(listener.Close() == nil)
        waitGroup.Wait()
    }

    var connectionId uint32 = 0
    for acceptingClients.Load() { // TODO: forbid logging in with credentials of an user which has already logged in and is still connected

        if connectionIdPtr := net.connectionIdsPool.TakeId(); connectionIdPtr == nil {
            sendDenialOfService(listener)
            continue
        } else {
            connectionId = *connectionIdPtr
        }

        connection, err := listener.Accept()
        if err != nil { break }

        waitGroup.Add(1)
        go processClient(&connection, connectionId, &waitGroup, &onShutDownRequested)
    }
}

func sendDenialOfService(listener goNet.Listener) {
    connection, err := listener.Accept()
    utils.Assert(err == nil)

    send(&connection, crypto.Sign(make([]byte, crypto.KeySize)))

    err = connection.Close()
    utils.Assert(err == nil)
}

func processClient(connection *goNet.Conn, connectionId uint32, waitGroup *goSync.WaitGroup, onShutDownRequested *func()) {
    utils.Assert(waitGroup != nil && onShutDownRequested != nil)

    closeConnection := func(disconnectedByClient bool) {
        if disconnectedByClient {
            utils.Assert(getConnectedUser(connectionId) != nil)
            onConnectionClosed(connectionId)
        } else {
            utils.Assert(getConnectedUser(connectionId) == nil)
        }

        net.connectionIdsPool.ReturnId(connectionId)
        waitGroup.Done()

        utils.Assert((*connection).Close() == nil)
    }

    send(connection, crypto.Sign(net.serverPublicKey))

    clientPublicKey := make([]byte, crypto.KeySize)
    receive(connection, clientPublicKey, nil)

    encryptionKey := crypto.ExchangeKeys(net.serverPublicKey, net.serverSecretKey, clientPublicKey)
    if encryptionKey == nil {
        closeConnection(false)
        return
    }
    addNewConnection(connectionId, connection, encryptionKey)

    messageBuffer := make([]byte, net.messageBufferSize)
    for {
        disconnected := false

        if receive(connection, messageBuffer, &disconnected) { // TODO: add timeout for an opened connection and limit connection count
            switch processClientMessage(connectionId, messageBuffer) {
                case flagFinishToReconnect: fallthrough // --& --x-- falling through until I decide what to do with them
                case flagFinishWithError: fallthrough
                case flagFinish:
                    closeConnection(false)
                    return
                case flagShutdown:
                    closeConnection(false)
                    (*onShutDownRequested)()
                    return
                case flagProceed: fallthrough // --x--
                case flagError: fallthrough
                case flagSuccess: func(){}()
            }
        }

        if disconnected {
            closeConnection(true)
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
    encryptionKey := getEncryptionKey(connectionId)
    utils.Assert(len(encryptionKey) > 0 && len(messageBytes) > 0)

    decrypted := crypto.Decrypt(messageBytes, encryptionKey)
    message := unpackMessage(decrypted)

    return routeMessage(connectionId, message)
}

func sendMessage(connectionId uint32, msg *message) {
    encryptionKey := getEncryptionKey(connectionId)
    utils.Assert(msg != nil && len(encryptionKey) > 0)

    connection := getConnection(connectionId)
    utils.Assert(connection != nil)

    packed := msg.pack()
    encrypted := crypto.Encrypt(packed, encryptionKey)

    send(connection, encrypted)
}
