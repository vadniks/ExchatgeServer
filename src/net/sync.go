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
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    "math"
    goSync "sync"
    "unsafe"
)

const flagProceed int32 = 0x00000000
const flagFinish int32 = 0x00000001
const flagFinishWithError int32 = 0x00000002
const flagFinishToReconnect int32 = 0x00000003 // after registration connection closes and client should reconnect & login
const flagLogIn int32 = 0x00000004
const flagLoggedIn int32 = 0x00000005
const flagRegister int32 = 0x00000006
const flagRegistered int32 = 0x00000007
const flagSuccess int32 = 0x00000008
const flagError int32 = 0x00000009
const flagUnauthenticated int32 = 0x0000000a
const flagAccessDenied int32 = 0x0000000b
const flagFetchUsers int32 = 0x0000000c
const flagFetchMessages int32 = 0x0000000d
const flagExchangeKeys = 0x000000a0
const flagExchangeKeysDone = 0x000000b0
const flagExchangeHeaders = 0x000000c0
const flagExchangeHeadersDone = 0x000000d0
const flagFileAsk = 0x000000e0
const flagFile = 0x000000f0
const flagShutdown int32 = 0x7fffffff

const toAnonymous uint32 = 0x7fffffff
const toServer uint32 = 0x7ffffffe

const stateConnected uint = 0
const stateSecureConnectionEstablished uint = 1
const stateLoggedWithCredentials uint = 2

const usernameSize uint = 16
const UnhashedPasswordSize uint = 16
const minCredentialSize = 4

const fromAnonymous uint32 = 0xffffffff
const fromServer uint32 = 0x7fffffff

type syncT struct {
    maxUsersCount uint32
    tokenAnonymous []byte
    tokenServer [crypto.TokenSize]byte
    bodyStub [messageBodySize]byte
    rwMutex goSync.RWMutex
    shuttingDown bool
}

var sync *syncT = nil

func syncInitialize(maxUsersCount uint) {
    sync = &syncT{
        uint32(maxUsersCount),
        make([]byte, crypto.TokenSize), // all zeroes
        crypto.MakeServerToken(messageBodySize),
        [messageBodySize]byte{}, // all zeroes,
        goSync.RWMutex{},
        false,
    }
}

func simpleServerMessage(xFlag int32, xTo uint32) *message {
    return &message{
        flag: xFlag,
        timestamp: utils.CurrentTimeMillis(),
        size: 0,
        index: 0,
        count: 1,
        from: fromServer,
        to: xTo,
        token: sync.tokenServer,
        body: sync.bodyStub,
    }
}

func serverMessage(xFlag int32, xTo uint32, xBody []byte) *message {
    bodySize := len(xBody)
    utils.Assert(bodySize > 0 && bodySize <= int(messageBodySize))

    result := &message{
        flag: xFlag,
        timestamp: utils.CurrentTimeMillis(),
        size: uint32(bodySize),
        index: 0,
        count: 1,
        from: fromServer,
        to: xTo,
        token: sync.tokenServer,
    }

    copy(unsafe.Slice(&(result.body[0]), messageBodySize), xBody)
    return result
}

func shutdownRequested(connectionId uint32, user *database.User, msg *message) int32 { // TODO: add more administrative actions, such as: logging in and registration blocking, user ban...
    utils.Assert(user != nil && msg.to == toServer)

    if database.IsAdmin(user) {
        finishRequested(connectionId)

        sync.rwMutex.Lock()
        sync.shuttingDown = true
        sync.rwMutex.Unlock()

        sync.rwMutex.Lock()
        database.DeleteAllMessagesFromAllUsers()
        sync.rwMutex.Unlock()

        return flagShutdown
    } else {
        sendMessage(connectionId, simpleServerMessage(flagAccessDenied, user.Id))
        return flagProceed
    }
}

//goland:noinspection GoRedundantConversion (*byte) - just silence that annoying warning already!
func proceedRequested(msg *message) int32 {
    utils.Assert(msg != nil && msg.to != msg.from)

    if toUserConnectionId, toUser := getAuthorizedConnectedUser(msg.to); toUser != nil {
        sendMessage(toUserConnectionId, msg)
    } // else user offline or doesn't exist

    sync.rwMutex.Lock()
    database.AddMessage(msg.timestamp, msg.from, msg.to, msg.body[:])
    sync.rwMutex.Unlock()

    return flagProceed
}

func parseCredentials(msg *message) (username []byte, unhashedPassword []byte) {
    utils.Assert(msg != nil && (msg.flag == flagLogIn || msg.flag == flagRegister))

    username = make([]byte, usernameSize)
    copy(username, unsafe.Slice(&(msg.body[0]), usernameSize))

    unhashedPassword = make([]byte, UnhashedPasswordSize)
    copy(unhashedPassword, unsafe.Slice(&(msg.body[usernameSize]), crypto.HashSize))

    return username, unhashedPassword
}

func loggingInWithCredentialsRequested(connectionId uint32, msg *message) int32 { // expects the password not to be hashed in order to compare it with salted hash (which is always different)
    utils.Assert(msg != nil)
    username, unhashedPassword := parseCredentials(msg)

    xUsernameSize := uint(len(username)); passwordSize := uint(len(unhashedPassword))
    utils.Assert(
        xUsernameSize > 0 && xUsernameSize <= usernameSize &&
        passwordSize > 0 && passwordSize <= UnhashedPasswordSize,
    )

    sync.rwMutex.Lock()
    user := database.FindUser(username, unhashedPassword)

    var connectedUser *database.User = nil
    if user != nil { _, connectedUser = getAuthorizedConnectedUser(user.Id) }

    if user == nil || connectedUser != nil {
        sync.rwMutex.Unlock()
        sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
        finishRequested(connectionId)
        return flagFinishWithError
    }

    setUser(connectionId, user)
    setConnectionState(connectionId, stateLoggedWithCredentials)

    token := crypto.MakeToken(connectionId, user.Id) // won't compile if inline the variable
    sync.rwMutex.Unlock()
    sendMessage(connectionId, serverMessage(flagLoggedIn, user.Id, token[:])) // here's how a client obtains his id
    return flagProceed
}

func registrationWithCredentialsRequested(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)

    sync.rwMutex.Lock()
    if database.GetUsersCount() >= sync.maxUsersCount {
        sync.rwMutex.Unlock()
        sendMessage(connectionId, simpleServerMessage(flagError, toAnonymous))
        finishRequested(connectionId)
        return flagFinishWithError
    }

    countZeroes := func(bytes []byte) uint {
        var zeroes uint = 0
        for _, i := range bytes {
            if i == 0 || i == byte(' ') { zeroes++ }
        }
        return zeroes
    }

    username, unhashedPassword := parseCredentials(msg)
    var user *database.User = nil

    usernameNonZeroes := usernameSize - countZeroes(username)
    unhashedPasswordNonZeroes := UnhashedPasswordSize - countZeroes(unhashedPassword)

    if usernameNonZeroes >= minCredentialSize && usernameNonZeroes <= usernameSize &&
        unhashedPasswordNonZeroes >= minCredentialSize && unhashedPasswordNonZeroes <= UnhashedPasswordSize {
        user = database.AddUser(username, crypto.Hash(unhashedPassword))
    }

    successful := user != nil

    sync.rwMutex.Unlock()
    sendMessage(connectionId, simpleServerMessage( // Lack of ternary operator is awful
        func() int32 { if successful { return flagRegistered } else { return flagError } }(),
        func() uint32 { if successful { return user.Id } else { return toAnonymous } }(),
    ))

    finishRequested(connectionId)
    if successful { return flagFinishToReconnect } else { return flagFinishWithError }
}

func finishRequested(connectionId uint32) int32 {
    sync.rwMutex.Lock()
    deleteConnection(connectionId)
    sync.rwMutex.Unlock()
    return flagFinish
}

//goland:noinspection GoRedundantConversion
func usersListRequested(connectionId uint32, userId uint32) int32 {
    sync.rwMutex.RLock()
    registeredUsers := database.GetAllUsers()
    var userInfosBytes []byte

    infosPerMessage := uint32(messageBodySize / userInfoSize)
    utils.Assert(infosPerMessage <= uint32(messageBodySize))
    stubBytes := make([]byte, uint32(messageBodySize) - infosPerMessage * uint32(userInfoSize))

    var infosCount uint32 = 0
    for _, user := range registeredUsers {
        _, xUser := getAuthorizedConnectedUser(user.Id)

        xUserInfo := &userInfo{
            id: user.Id,
            connected: xUser != nil,
            name: [16]byte{},
        }
        copy(unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.name))), usernameSize), user.Name)

        userInfosBytes = append(userInfosBytes, xUserInfo.pack()...)
        infosCount++

        if infosCount % infosPerMessage == 0 {
            userInfosBytes = append(userInfosBytes, stubBytes...)
        }
    }

    messagesCount := uint32(math.Ceil(float64(infosCount) / float64(infosPerMessage)))
    totalPayloadBytesSize := messagesCount * uint32(messageBodySize)
    userInfosBytes = append(userInfosBytes, make([]byte, totalPayloadBytesSize - uint32(len(userInfosBytes)))...)
    utils.Assert(uint32(len(userInfosBytes)) == totalPayloadBytesSize)

    var infosCountInMessage uint32
    for messageIndex := uint32(0); messageIndex < messagesCount; messageIndex++ {

        if infosCount > infosPerMessage * (messageIndex + 1) {
            infosCountInMessage = infosPerMessage
        } else {
            infosCountInMessage = infosCount - infosPerMessage * messageIndex
        }

        msg := &message{
            flag: flagFetchUsers,
            timestamp: utils.CurrentTimeMillis(),
            size: infosCountInMessage,
            index: messageIndex,
            count: messagesCount,
            from: fromServer,
            to: userId,
            token: sync.tokenServer,
            body: [messageBodySize]byte{},
        }

        copy(
           unsafe.Slice((*byte) (unsafe.Pointer(&(msg.body))), messageBodySize),
           unsafe.Slice((*byte) (unsafe.Pointer(&(userInfosBytes[messageIndex * uint32(messageBodySize)]))), messageBodySize),
        )

        sendMessage(connectionId, msg)
    }

    sync.rwMutex.RUnlock()
    return flagProceed
}

//goland:noinspection GoRedundantConversion
func messagesRequested(connectionId uint32, msg *message) int32 {
    const byteSize = 1
    utils.Assert(unsafe.Sizeof(true) == byteSize)
    const intSize = unsafe.Sizeof(int32(0))
    const longSize = unsafe.Sizeof(int64(0))

    fromMode := msg.body[0]
    utils.Assert(fromMode == 0 || fromMode == 1)

    var afterTimestamp uint64
    copy(unsafe.Slice((*byte) (unsafe.Pointer(&afterTimestamp)), longSize), unsafe.Slice((*byte) (&(msg.body[byteSize])), longSize))
    utils.Assert(afterTimestamp < utils.CurrentTimeMillis())

    var fromUser uint32
    if fromMode == 0 {
        copy(unsafe.Slice((*byte) (unsafe.Pointer(&fromUser)), intSize), unsafe.Slice((*byte) (&(msg.body[byteSize + longSize])), intSize))
        utils.Assert(fromUser < sync.maxUsersCount)
    } else {
        fromUser = msg.from
    }

    if !database.UserExists(fromUser) {
        sendMessage(connectionId, simpleServerMessage(flagError, msg.from))
        return flagError
    }

    sync.rwMutex.RLock()
    messages := database.GetMessagesFromOrForUser(fromMode == 1, fromUser, afterTimestamp)
    sync.rwMutex.RUnlock()

    count := len(messages)
    var lastMessageTimestamp uint64 = 0

    if count == 0 {
        reply := &message{
            flagFetchMessages,
            utils.CurrentTimeMillis(),
            0,
            0,
            1,
            fromServer,
            msg.from,
            sync.tokenServer,
            [messageBodySize]byte{},
        }

        reply.body[0] = fromMode
        copy(unsafe.Slice((*byte) (&(reply.body[byteSize])), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&afterTimestamp)), longSize))
        copy(unsafe.Slice((*byte) (&(reply.body[byteSize + longSize])), longSize), unsafe.Slice((*byte) (unsafe.Pointer(&fromUser)), longSize))

        sendMessage(connectionId, reply)
        return flagProceed
    }

    for index, xMessage := range messages {
        newMsg := &message{
            flagFetchMessages,
            utils.CurrentTimeMillis(),
            uint32(len(xMessage.Body)),
            uint32(index),
            uint32(count),
            xMessage.From,
            msg.from,
            sync.tokenServer,
            [messageBodySize]byte{},
        }

        copy(
            unsafe.Slice((*byte) (unsafe.Pointer(&(newMsg.body[0]))), messageBodySize),
            unsafe.Slice((*byte) (unsafe.Pointer(&(xMessage.Body[0]))), len(xMessage.Body)),
        )

        sendMessage(connectionId, newMsg)

        if timestamp := xMessage.Timestamp; lastMessageTimestamp < timestamp {
            lastMessageTimestamp = timestamp
        }
    }

    sync.rwMutex.Lock()
    database.DeleteMessagesFromOrForUser(fromMode == 1, fromUser, lastMessageTimestamp)
    sync.rwMutex.Unlock()

    return flagProceed
}

func routeMessage(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)
    flag := msg.flag
    xConnectionId, userIdFromToken := crypto.OpenToken(msg.token)

    sync.rwMutex.Lock()

    state := getConnectionState(connectionId)
    utils.Assert(state != nil)
    userId := getConnectedUserId(connectionId)

    if flag == flagLogIn || flag == flagRegister {
        utils.Assert(
            *state == 0 && // state associated with this connectionId exist yet (non-existent map entry defaults to typed zero value)
            msg.from == fromAnonymous &&
            xConnectionId == nil &&
            userIdFromToken == nil &&
            msg.to == toServer,
        )

        setConnectionState(connectionId, stateSecureConnectionEstablished)
    } else {
        utils.Assert(
            *state > 0 &&
            userId != nil &&
            msg.from != fromAnonymous &&
            msg.from != fromServer,
        )

        if xConnectionId == nil ||
            userIdFromToken == nil ||
            *xConnectionId != connectionId ||
            *userIdFromToken != *userId ||
            msg.from != *userIdFromToken {

            sync.rwMutex.Unlock()

            sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
            finishRequested(connectionId)
            return flagFinishWithError
        }
    }

    shuttingDown := sync.shuttingDown
    sync.rwMutex.Unlock()

    if shuttingDown {
        sendMessage(connectionId, simpleServerMessage(flagError, *userId))
        finishRequested(connectionId)
        return flagFinishWithError
    }

    switch flag {
        case flagShutdown:
            return shutdownRequested(connectionId, getUser(connectionId), msg)
        case flagExchangeKeys: fallthrough
        case flagExchangeKeysDone: fallthrough
        case flagExchangeHeaders: fallthrough
        case flagExchangeHeadersDone: fallthrough
        case flagFileAsk: fallthrough
        case flagFile: fallthrough
        case flagProceed:
            return proceedRequested(msg)
        case flagLogIn:
            utils.Assert(msg.to == toServer)
            return loggingInWithCredentialsRequested(connectionId, msg)
        case flagRegister:
            utils.Assert(msg.to == toServer)
            return registrationWithCredentialsRequested(connectionId, msg)
        case flagFinish:
            utils.Assert(msg.to == toServer)
            utils.Assert(msg.to == toServer)
            return finishRequested(connectionId)
        case flagFetchUsers:
            utils.Assert(msg.to == toServer)
            return usersListRequested(connectionId, *userIdFromToken)
        case flagFetchMessages:
            utils.Assert(msg.to == toServer)
            return messagesRequested(connectionId, msg)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func onConnectionClosed(connectionId uint32) { finishRequested(connectionId) }
