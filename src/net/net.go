/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023  Vadim Nikolaev (https://github.com/vadniks)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/idsPool"
    "ExchatgeServer/utils"
    "fmt"
    goNet "net"
    goSync "sync"
    "sync/atomic"
    "time"
"unsafe"
)

const intSize = 4
const longSize = 8

const messageSize uint = 1 << 10 // exactly 1 kB
const messageHeadSize = intSize * 6 + longSize + crypto.TokenSize // 96
const messageBodySize = messageSize - messageHeadSize // 928
const userInfoSize = intSize + 1/*sizeof(bool)*/ + usernameSize // 21

const maxTimeMillisToPreserveActiveConnection = 1000 * 60 * 60 // 1 hour
const maxTimeMillisIntervalBetweenMessages = 1000 * 60 * 10 // 10 minutes

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

func Initialize(maxUsersCount uint) {
    var byteOrderChecker uint64 = 0x0123456789abcdef // only on x64 littleEndian data marshalling will work as clients expect
    utils.Assert(unsafe.Sizeof(uintptr(0)) == 8 && *((*uint8) (unsafe.Pointer(&byteOrderChecker))) == 0xef)

    serverPublicKey, serverSecretKey := crypto.GenerateServerKeys()

    net = &netT{
       serverPublicKey,
       serverSecretKey,
       crypto.EncryptedSize(messageSize),
        idsPool.InitIdsPool(uint32(maxUsersCount)),
    }

    syncInitialize(maxUsersCount)
}

func ProcessClients(host string, port uint) {
    listener, err := goNet.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
    utils.Assert(err == nil)

    var waitGroup goSync.WaitGroup

    var acceptingClients atomic.Bool
    acceptingClients.Store(true)

    onShutDownRequested := func() { // TODO: add timeouts for connections
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

func updateConnectionIdleTimeout(connection *goNet.Conn) {
    err := (*connection).SetDeadline(time.UnixMilli(int64(utils.CurrentTimeMillis()) + maxTimeMillisIntervalBetweenMessages))
    utils.Assert(err == nil)
}

func processClient(connection *goNet.Conn, connectionId uint32, waitGroup *goSync.WaitGroup, onShutDownRequested *func()) {
    utils.Assert(waitGroup != nil && onShutDownRequested != nil)

    updateConnectionIdleTimeout(connection)

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
    if !receive(connection, clientPublicKey, nil) {
        closeConnection(false)
        return
    }

    serverKey, clientKey := crypto.ExchangeKeys(net.serverPublicKey, net.serverSecretKey, clientPublicKey)
    if serverKey == nil || clientKey == nil {
        closeConnection(false)
        return
    }

    serverStreamHeader, xCrypto := crypto.CreateEncoderStream(serverKey)
    send(connection, crypto.Sign(serverStreamHeader))

    clientStreamHeader := make([]byte, crypto.HeaderSize)
    if !receive(connection, clientStreamHeader, nil) {
        closeConnection(false)
        return
    }

    if !xCrypto.CreateDecoderStream(clientKey, clientStreamHeader) {
        closeConnection(false)
        return
    }

    connectedAt := utils.CurrentTimeMillis()
    addNewConnection(connectionId, connection, xCrypto)

    messageBuffer := make([]byte, net.messageBufferSize)
    for {
        disconnected := false

        if utils.CurrentTimeMillis() - connectedAt < maxTimeMillisToPreserveActiveConnection &&
            receive(connection, messageBuffer, &disconnected) {

            switch processClientMessage(connectionId, messageBuffer) {
                case flagFinishToReconnect: fallthrough
                case flagFinishWithError: fallthrough
                case flagFinish:
                    closeConnection(false)
                    return
                case flagShutdown:
                    closeConnection(false)
                    (*onShutDownRequested)()
                    return
                default: {}
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

    updateConnectionIdleTimeout(connection)
}

func receive(connection *goNet.Conn, buffer []byte, /*nillable*/ error *bool) bool {
    utils.Assert(connection != nil && len(buffer) > 0)

    count, err := (*connection).Read(buffer)
    if error != nil { *error = err != nil }
    if err != nil { return false }

    updateConnectionIdleTimeout(connection)

    return count == len(buffer)
}

func processClientMessage(connectionId uint32, messageBytes []byte) int32 {
    xCrypto := getCrypto(connectionId)
    utils.Assert(xCrypto != nil && len(messageBytes) > 0)

    decrypted := xCrypto.Decrypt(messageBytes)
    message := unpackMessage(decrypted)

    return routeMessage(connectionId, message)
}

func sendMessage(connectionId uint32, msg *message) {
    xCrypto := getCrypto(connectionId)
    utils.Assert(msg != nil && xCrypto != nil)

    connection := getConnection(connectionId)
    utils.Assert(connection != nil)

    packed := msg.pack()
    encrypted := xCrypto.Encrypt(packed)

    send(connection, encrypted)
}
