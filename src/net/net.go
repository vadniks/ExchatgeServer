/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023-2024  Vadim Nikolaev (https://github.com/vadniks)
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

const maxMessageSize uint = 1 << 8 // 256
const messageHeadSize = intSize * 6 + longSize + crypto.TokenSize // 96
const maxMessageBodySize = maxMessageSize - messageHeadSize // 160
const userInfoSize = intSize + 1/*sizeof(bool)*/ + usernameSize // 21

const timeout = 5000 // milliseconds

type netT struct {
    maxTimeMillisToPreserveActiveConnection uint64
    maxTimeMillisIntervalBetweenMessages uint64
    serverPublicKey []byte
    serverSecretKey []byte
    connectionIdsPool *idsPool.IdsPool
}
var Net *netT = nil // aka singleton

type message struct {
    flag int32
    timestamp uint64
    size uint32
    index uint32
    count uint32
    from uint32
    to uint32
    token [crypto.TokenSize]byte
    body []byte // nillable
}

type userInfo struct {
    id uint32
    connected bool
    name [usernameSize]byte
}

func (_ *netT) wholeMessageBytesSize(size uint32) uint32 { return uint32(messageHeadSize) + size }

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (net *netT) packMessage(msg *message) []byte {
    utils.Assert(msg != nil)

    utils.Assert(msg.body == nil && msg.size == 0 ||
        msg.body != nil && msg.size != 0 && uint32(len(msg.body)) == msg.size && msg.size <= uint32(maxMessageBodySize))

    bytes := make([]byte, net.wholeMessageBytesSize(msg.size))

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.flag))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.timestamp))), longSize))
    copy(unsafe.Slice(&(bytes[intSize + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.size))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.index))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.count))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.from))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.to))), intSize))
    copy(unsafe.Slice(&(bytes[intSize * 6 + longSize]), crypto.TokenSize), unsafe.Slice((*byte) (unsafe.Pointer(&(msg.token))), crypto.TokenSize))

    if msg.body != nil { copy(unsafe.Slice(&(bytes[messageHeadSize]), msg.size), unsafe.Slice(&(msg.body[0]), msg.size)) }
    return bytes
}

//goland:noinspection GoRedundantConversion (*byte) - won't compile without casting
func (_ *netT) unpackMessage(bytes []byte) *message {
    utils.Assert(len(bytes) > 0)
    msg := new(message)

    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.flag))), intSize), unsafe.Slice(&(bytes[0]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.timestamp))), longSize), unsafe.Slice(&(bytes[intSize]), longSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.size))), intSize), unsafe.Slice(&(bytes[intSize + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.index))), intSize), unsafe.Slice(&(bytes[intSize * 2 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.count))), intSize), unsafe.Slice(&(bytes[intSize * 3 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.from))), intSize), unsafe.Slice(&(bytes[intSize * 4 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.to))), intSize), unsafe.Slice(&(bytes[intSize * 5 + longSize]), intSize))
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&(msg.token))), crypto.TokenSize), unsafe.Slice(&(bytes[intSize * 6 + longSize]), crypto.TokenSize))

    utils.Assert(msg.size <= uint32(maxMessageBodySize))
    if msg.size > 0 {
        msg.body = make([]byte, msg.size)
        copy(unsafe.Slice(&(msg.body[0]), msg.size), unsafe.Slice(&(bytes[messageHeadSize]), msg.size))
    } else {
        msg.body = nil
    }

    return msg
}

//goland:noinspection GoRedundantConversion
func (_ *netT) packUserInfo(xUserInfo *userInfo) []byte {
    utils.Assert(unsafe.Sizeof(false) == 1)
    bytes := make([]byte, userInfoSize)

    copy(unsafe.Slice(&(bytes[0]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.id))), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), 1), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.connected))), 1))
    copy(unsafe.Slice(&(bytes[intSize + 1]), usernameSize), unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.name))), usernameSize))

    return bytes
}

func Initialize(maxUsersCount uint, maxTimeMillisToPreserveActiveConnection uint, maxTimeMillisIntervalBetweenMessages uint) {
    var byteOrderChecker uint64 = 0x0123456789abcdef // only on x64 littleEndian data marshalling will work as clients expect
    utils.Assert(unsafe.Sizeof(uintptr(0)) == 8 && *((*uint8) (unsafe.Pointer(&byteOrderChecker))) == 0xef)

    serverPublicKey, serverSecretKey := crypto.GenerateServerKeys()

    utils.Assert(Net == nil)
    Net = &netT{
        uint64(maxTimeMillisToPreserveActiveConnection),
        uint64(maxTimeMillisIntervalBetweenMessages),
        serverPublicKey,
        serverSecretKey,
        idsPool.InitIdsPool(uint32(maxUsersCount)),
    }

    syncInitialize(maxUsersCount)
}

func (net *netT) ProcessClients(host string, port uint) {
    utils.Assert(net != nil)
    listener, err := goNet.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
    utils.Assert(err == nil)

    var waitGroup goSync.WaitGroup

    var acceptingClients atomic.Bool
    acceptingClients.Store(true)

    onShutDownRequested := func() {
        acceptingClients.Store(false)
        utils.Assert(listener.Close() == nil)
        waitGroup.Wait()
    }

    go net.watchConnectionTimeouts(&acceptingClients)

    var connectionId uint32 = 0
    for acceptingClients.Load() { // TODO: forbid logging in with credentials of an user which has already logged in and is still connected

        if connectionIdPtr := net.connectionIdsPool.TakeId(); connectionIdPtr == nil {
            net.sendDenialOfService(listener)
            continue
        } else {
            connectionId = *connectionIdPtr
        }

        connection, err := listener.Accept()
        if err != nil { break }

        waitGroup.Add(1)
        go net.processClient(&connection, connectionId, &waitGroup, &onShutDownRequested)
    }
}

func (_ *netT) sendDenialOfService(listener goNet.Listener) {
    connection, err := listener.Accept()
    utils.Assert(err == nil)

    Net.send(&connection, crypto.Sign(make([]byte, crypto.KeySize)))

    err = connection.Close()
    utils.Assert(err == nil)
}

func (_ *netT) watchConnectionTimeouts(acceptingClients *atomic.Bool) {
    for acceptingClients.Load() {
        connections.checkConnectionTimeouts(func(xConnectedUser *connectedUser) {
            utils.Assert((*(xConnectedUser.connection)).SetDeadline(time.UnixMilli(int64(utils.CurrentTimeMillis() + 100))) == nil)
        })
        time.Sleep(1e8) // 100 milliseconds = 100 * 1000 000 nanoseconds = 0.1 seconds
    }
}

func (_ *netT) updateConnectionIdleTimeout(connection *goNet.Conn) {
    err := (*connection).SetDeadline(time.UnixMilli(int64(utils.CurrentTimeMillis()) + int64(Net.maxTimeMillisIntervalBetweenMessages)))
    utils.Assert(err == nil)
}

func (net *netT) processClient(connection *goNet.Conn, connectionId uint32, waitGroup *goSync.WaitGroup, onShutDownRequested *func()) {
    utils.Assert(waitGroup != nil && onShutDownRequested != nil)

    net.updateConnectionIdleTimeout(connection)

    closeConnection := func(disconnectedByClient bool) {
        if disconnectedByClient {
            utils.Assert(connections.getConnectedUser(connectionId) != nil)
            connections.deleteConnection(connectionId)
        } else {
            utils.Assert(connections.getConnectedUser(connectionId) == nil)
        }

        net.connectionIdsPool.ReturnId(connectionId)
        waitGroup.Done()

        utils.Assert((*connection).Close() == nil)
    }

    net.send(connection, crypto.Sign(net.serverPublicKey))

    clientPublicKey := make([]byte, crypto.KeySize)
    if !net.receive(connection, clientPublicKey, nil) {
        closeConnection(false)
        return
    }

    serverKey, clientKey := crypto.ExchangeKeys(net.serverPublicKey, net.serverSecretKey, clientPublicKey)
    if serverKey == nil || clientKey == nil {
        closeConnection(false)
        return
    }

    serverStreamHeader, xCrypto := crypto.CreateEncoderStream(serverKey)
    net.send(connection, crypto.Sign(serverStreamHeader))

    clientStreamHeader := make([]byte, crypto.HeaderSize)
    if !net.receive(connection, clientStreamHeader, nil) {
        closeConnection(false)
        return
    }

    if !xCrypto.CreateDecoderStream(clientKey, clientStreamHeader) {
        closeConnection(false)
        return
    }

    connections.addNewConnection(connectionId, connection, xCrypto)
    for {
        disconnected := false

        if messageBuffer := net.receiveEncryptedMessageBytes(connection, &disconnected); messageBuffer != nil {
            switch net.processEncryptedClientMessage(connectionId, messageBuffer) {
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

        time.Sleep(1e7 * 5) // 0.05 seconds
    }
}

func (net *netT) send(connection *goNet.Conn, payload []byte) {
    utils.Assert(connection != nil && len(payload) > 0)

    count, err := (*connection).Write(payload)
    utils.Assert(count == len(payload) && err == nil) // TODO: remove assert - just ignore // if !-first- || !-second- { return }

    net.updateConnectionIdleTimeout(connection)
}

func (net *netT) receive(connection *goNet.Conn, buffer []byte, /*nillable*/ error *bool) bool {
    utils.Assert(connection != nil && len(buffer) > 0)

    count, err := (*connection).Read(buffer)
    if error != nil { *error = err != nil }
    if err != nil { return false }

    net.updateConnectionIdleTimeout(connection)

    return count == len(buffer)
}

func (_ *netT) setConnectionTimeoutBetweenMessageParts(connection *goNet.Conn) {
    err := (*connection).SetDeadline(time.UnixMilli(int64(utils.CurrentTimeMillis()) + int64(timeout))) // wait for $timeout, which is less than used in updateIdleTimeout, as right after the size the actual message must come, timeout then will be reset to default by receive()
    utils.Assert(err == nil)
}

//goland:noinspection GoRedundantConversion
func (net *netT) receiveEncryptedMessageBytes(connection *goNet.Conn, error *bool) []byte { // nillable result
    utils.Assert(error != nil)

    var size uint32 = 0
    if !net.receive(connection, unsafe.Slice((*byte) (unsafe.Pointer(&size)), intSize), error) { return nil }
    utils.Assert(!*error && size > 0 && size <= uint32(crypto.EncryptedSize(maxMessageSize)))

    net.setConnectionTimeoutBetweenMessageParts(connection)

    buffer := make([]byte, size)
    if !net.receive(connection, buffer, error) { return nil }

    return buffer
}

func (net *netT) processEncryptedClientMessage(connectionId uint32, messageBytes []byte) int32 {
    coders := connections.getCoders(connectionId)
    utils.Assert(coders != nil && len(messageBytes) > 0 && uint(len(messageBytes)) <= crypto.EncryptedSize(maxMessageSize))

    decrypted := coders.Decrypt(messageBytes)
    utils.Assert(len(decrypted) > 0 && len(decrypted) <= int(maxMessageSize))
    message := net.unpackMessage(decrypted)

    return routeMessage(connectionId, message)
}

//goland:noinspection GoRedundantConversion
func (net *netT) sendMessage(connectionId uint32, msg *message) {
    utils.Assert(int(msg.size) == len(msg.body) && msg.size <= uint32(maxMessageBodySize))

    coders := connections.getCoders(connectionId)
    utils.Assert(msg != nil && coders != nil) // TODO: instead of asserting just return

    connection := connections.getConnection(connectionId)
    utils.Assert(connection != nil)

    packed := net.packMessage(msg)
    encrypted := coders.Encrypt(packed)
    utils.Assert(len(encrypted) > 0 && uint(len(encrypted)) <= crypto.EncryptedSize(maxMessageSize) && int(crypto.EncryptedSize(uint(len(packed)))) == len(encrypted))

    encryptedSize := uint32(len(encrypted))

    buffer := make([]byte, intSize + encryptedSize)
    copy(buffer, unsafe.Slice((*byte) (unsafe.Pointer(&encryptedSize)), intSize))
    copy(unsafe.Slice(&(buffer[intSize]), encryptedSize), encrypted)

    net.send(connection, buffer)
}
