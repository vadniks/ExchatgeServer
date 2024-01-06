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
const flagBroadcast int32 = 0x10000000
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
    rwMutex goSync.RWMutex
    shuttingDown bool
}

var sync *syncT = nil

func syncInitialize(maxUsersCount uint) {
    sync = &syncT{
        uint32(maxUsersCount),
        make([]byte, crypto.TokenSize), // all zeroes
        crypto.MakeServerToken(maxMessageBodySize),
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
        body: nil,
    }
}

func serverMessage(xFlag int32, xTo uint32, xBody []byte /*nillable*/) *message {
    bodySize := len(xBody)
    utils.Assert(bodySize > 0 && bodySize <= int(maxMessageBodySize))

    result := &message{
        flag: xFlag,
        timestamp: utils.CurrentTimeMillis(),
        size: uint32(bodySize),
        index: 0,
        count: 1,
        from: fromServer,
        to: xTo,
        token: sync.tokenServer,
        body: xBody,
    }

    return result
}

func kickUserCuzOfDenialOfAccess(connectionId uint32, userId uint32) int32 {
    sendMessage(connectionId, simpleServerMessage(flagAccessDenied, userId))
    finishRequested(connectionId)
    return flagFinishWithError
}

func shutdownRequested(connectionId uint32, user *database.User, msg *message) int32 { // TODO: add more administrative actions, such as: logging in and registration blocking, user ban...
    utils.Assert(user != nil && msg.to == toServer && msg.size == 0)
    if !database.IsAdmin(user) { return kickUserCuzOfDenialOfAccess(connectionId, user.Id) }

    finishRequested(connectionId)

    sync.rwMutex.Lock()
    sync.shuttingDown = true
    sync.rwMutex.Unlock()

    sync.rwMutex.Lock()
    database.DeleteAllMessagesFromAllUsers()
    sync.rwMutex.Unlock()

    return flagShutdown
}

func broadcastRequested(connectionId uint32, user *database.User, msg *message) int32 {
    utils.Assert(user != nil && msg.to == toServer && msg.size > 0 && msg.body != nil)
    if !database.IsAdmin(user) { return kickUserCuzOfDenialOfAccess(connectionId, user.Id) }

    doForEachConnectedAuthorizedUser(func(connectionId uint32, xUser *connectedUser) {
        if xUser.user.Id == user.Id { return }
        sendMessage(connectionId, &message{ // TODO: move outside lambda and only change the toId
            flag: flagBroadcast,
            timestamp: utils.CurrentTimeMillis(),
            size: msg.size,
            index: 0,
            count: 1,
            from: fromServer,
            to: xUser.user.Id,
            token: sync.tokenServer,
            body: msg.body,
        })
    })

    return flagProceed
}

func proceedRequested(msg *message) int32 {
    utils.Assert(msg != nil && msg.to != msg.from && msg.size > 0 && msg.body != nil)

    if toUserConnectionId, toUser := getAuthorizedConnectedUser(msg.to); toUser != nil {
        sendMessage(toUserConnectionId, msg)
    }

    if msg.flag != flagProceed { return flagProceed } // since this function is called not only with actual proceed but with exchange* flags too. Others are ignored by the server cuz it's clients' deal to handle 'em

    sync.rwMutex.Lock() // save messages only with proceed flag
    database.AddMessage(msg.timestamp, msg.from, msg.to, msg.body)
    sync.rwMutex.Unlock()

    return flagProceed
}

func parseCredentials(msg *message) (username []byte, unhashedPassword []byte) {
    utils.Assert(msg != nil && (msg.flag == flagLogIn || msg.flag == flagRegister))

    username = make([]byte, usernameSize)
    copy(username, unsafe.Slice(&(msg.body[0]), usernameSize))

    unhashedPassword = make([]byte, UnhashedPasswordSize)
    copy(unhashedPassword, unsafe.Slice(&(msg.body[usernameSize]), UnhashedPasswordSize))

    return username, unhashedPassword
}

func loggingInWithCredentialsRequested(connectionId uint32, msg *message) int32 { // expects the password not to be hashed in order to compare it with salted hash (which is always different)
    utils.Assert(msg != nil && msg.size > 0 && msg.body != nil)
    username, unhashedPassword := parseCredentials(msg)

    xUsernameSize := uint(len(username)); passwordSize := uint(len(unhashedPassword))
    utils.Assert(
        xUsernameSize > 0 && xUsernameSize <= usernameSize &&
        passwordSize > 0 && passwordSize <= UnhashedPasswordSize,
    )

    sync.rwMutex.Lock()
    user := database.FindUser(username, unhashedPassword)

    var xConnectedUser *database.User = nil
    if user != nil { _, xConnectedUser = getAuthorizedConnectedUser(user.Id) }

    if user == nil || xConnectedUser != nil {
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
    utils.Assert(msg != nil && msg.size > 0 && msg.body != nil)

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
    sync.rwMutex.Lock() // TODO: redundant locks usage here
    deleteConnection(connectionId)
    sync.rwMutex.Unlock()
    return flagFinish
}

//goland:noinspection GoRedundantConversion
func usersListRequested(connectionId uint32, userId uint32) int32 {
    sync.rwMutex.RLock()

    registeredUsers := database.GetAllUsers()
    var userInfosBytes []byte

    infosPerMessage := uint32(math.Floor(float64(maxMessageBodySize) / float64(userInfoSize)))
    utils.Assert(infosPerMessage <= uint32(maxMessageBodySize))

    totalInfosCount := uint32(len(registeredUsers))
    messagesCount := uint32(math.Ceil(float64(totalInfosCount) / float64(infosPerMessage)))

    messageIndex := uint32(0)
    totalRemainingInfos := len(registeredUsers)
    infosCount := uint32(0)

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
        totalRemainingInfos--

        if infosCount < infosPerMessage && totalRemainingInfos > 0 { continue }
        size := infosCount * uint32(userInfoSize)
        println(len(userInfosBytes), int(size), infosCount, totalRemainingInfos)
        utils.Assert(len(userInfosBytes) == int(size))

        sendMessage(connectionId, &message{
            flag: flagFetchUsers,
            timestamp: utils.CurrentTimeMillis(),
            size: size,
            index: messageIndex,
            count: messagesCount,
            from: fromServer,
            to: userId,
            token: sync.tokenServer,
            body: userInfosBytes,
        })
        messageIndex++

        userInfosBytes = []byte{}
        infosCount = 0
    }

    sync.rwMutex.RUnlock()
    return flagProceed
}

//goland:noinspection GoRedundantConversion
func messagesRequested(connectionId uint32, msg *message) int32 {
    utils.Assert(msg.size > 0 && msg.body != nil)

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
        fromUser = msg.from
    } else {
        copy(unsafe.Slice((*byte) (unsafe.Pointer(&fromUser)), intSize), unsafe.Slice((*byte) (&(msg.body[byteSize + longSize])), intSize))
        utils.Assert(fromUser < sync.maxUsersCount)
    }

    if !database.UserExists(fromUser) {
        sendMessage(connectionId, simpleServerMessage(flagError, msg.from))
        return flagError
    }

    sync.rwMutex.RLock()
    messages := database.GetMessagesFromOrForUser(fromMode == 1, fromUser, afterTimestamp)
    sync.rwMutex.RUnlock()

    count := len(messages)

    if count == 0 {
        replyBody := make([]byte, 1)
        replyBody[0] = fromMode
        replyBody = append(replyBody, unsafe.Slice((*byte) (unsafe.Pointer(&afterTimestamp)), longSize)...)
        replyBody = append(replyBody, unsafe.Slice((*byte) (unsafe.Pointer(&fromUser)), intSize)...)

        sendMessage(connectionId, &message{
            flagFetchMessages,
            utils.CurrentTimeMillis(),
            uint32(1 + longSize + intSize),
            0,
            1,
            fromServer,
            msg.from,
            sync.tokenServer,
            replyBody,
        })
        return flagProceed
    }

    for index, xMessage := range messages {
        sendMessage(connectionId, &message{
            flagFetchMessages,
            xMessage.Timestamp,
            uint32(len(xMessage.Body)),
            uint32(index),
            uint32(count),
            xMessage.From,
            msg.from,
            sync.tokenServer,
            xMessage.Body,
        })
    }

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

    interruptConnection := func(flag int32, to uint32) {
        sendMessage(connectionId, simpleServerMessage(flag, to))
        finishRequested(connectionId)
    }

    if flag == flagLogIn || flag == flagRegister {
        if !(*state == stateConnected && // state associated with this connectionId exist yet (non-existent map entry defaults to typed zero value)
            msg.from == fromAnonymous &&
            xConnectionId == nil &&
            userIdFromToken == nil &&
            msg.to == toServer) {

            sync.rwMutex.Unlock()
            interruptConnection(flagError, toAnonymous)
            return flagFinishWithError
        }

        setConnectionState(connectionId, stateSecureConnectionEstablished)
    } else {
        if !(*state > stateConnected &&
            userId != nil &&
            msg.from != fromAnonymous &&
            msg.from != fromServer) {

            sync.rwMutex.Unlock()
            interruptConnection(flagError, msg.from)
            return flagFinishWithError
        }

        if xConnectionId == nil ||
            userIdFromToken == nil ||
            *xConnectionId != connectionId ||
            *userIdFromToken != *userId ||
            msg.from != *userIdFromToken {

            sync.rwMutex.Unlock()
            interruptConnection(flagUnauthenticated, toAnonymous)
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

    doIfToServerOrInterrupt := func(action func() int32) int32 {
        if msg.to == toServer {
            return action()
        } else {
            interruptConnection(flagError, msg.from)
            return flagFinishWithError
        }
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
            return doIfToServerOrInterrupt(func() int32 { return loggingInWithCredentialsRequested(connectionId, msg) })
        case flagRegister:
            return doIfToServerOrInterrupt(func() int32 { return registrationWithCredentialsRequested(connectionId, msg) })
        case flagFinish:
            return doIfToServerOrInterrupt(func() int32 { return finishRequested(connectionId) })
        case flagFetchUsers:
            return doIfToServerOrInterrupt(func() int32 { return usersListRequested(connectionId, *userIdFromToken) })
        case flagFetchMessages:
            return doIfToServerOrInterrupt(func() int32 { return messagesRequested(connectionId, msg) })
        case flagBroadcast:
            return broadcastRequested(connectionId, getUser(connectionId), msg)
        default:
            interruptConnection(flagError, msg.from)
            return flagFinishWithError
    }
}
