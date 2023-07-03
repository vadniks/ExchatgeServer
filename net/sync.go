
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    "math"
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
const flagShutdown int32 = 0x7fffffff

const toAnonymous uint32 = 0x7fffffff
const toServer uint32 = 0x7ffffffe

const stateConnected uint = 0
const stateSecureConnectionEstablished uint = 1
const stateLoggedWithCredentials uint = 2

const usernameSize uint = 16
const unhashedPasswordSize uint = 16

const fromAnonymous uint32 = 0xffffffff
const fromServer uint32 = 0x7fffffff

type syncT struct {
    tokenAnonymous []byte
    tokenServer [crypto.TokenSize]byte
    bodyStub [messageBodySize]byte
}

var sync = &syncT{
    make([]byte, crypto.TokenSize), // all zeroes
    crypto.MakeServerToken(messageBodySize),
    [messageBodySize]byte{}, // all zeroes
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

func shutdownRequested(connectionId uint32, user *database.User, msg *message) int32 {
    utils.Assert(user != nil && msg.to == toServer)

    if database.IsAdmin(user) {
        finishRequested(connectionId)
        return flagShutdown
    } else {
        sendMessage(connectionId, simpleServerMessage(flagAccessDenied, user.Id))
        return flagProceed
    }
}

//goland:noinspection GoRedundantConversion (*byte) - just silence that annoying warning already!
func proceedRequested(msg *message) int32 {
    utils.Assert(msg != nil && msg.to != msg.from)

    if toUserConnectionId, toUser := findConnectUser(msg.to); toUser != nil {
        sendMessage(toUserConnectionId, msg)
    } else {
        // TODO: user offline or doesn't exist
    }
    return flagProceed
}

func parseCredentials(msg *message) (username []byte, unhashedPassword []byte) { // TODO: add token protection or encrypt/sign user id
    utils.Assert(msg != nil && (msg.flag == flagLogIn || msg.flag == flagRegister))

    username = make([]byte, usernameSize)
    copy(username, unsafe.Slice(&(msg.body[0]), usernameSize))

    unhashedPassword = make([]byte, unhashedPasswordSize)
    copy(unhashedPassword, unsafe.Slice(&(msg.body[usernameSize]), crypto.HashSize))

    return username, unhashedPassword
}

func loggingInWithCredentialsRequested(connectionId uint32, msg *message) int32 { // expects the password not to be hashed in order to compare it with salted hash (which is always different)
    utils.Assert(msg != nil)
    username, unhashedPassword := parseCredentials(msg)

    xUsernameSize := uint(len(username)); passwordSize := uint(len(unhashedPassword))
    utils.Assert(
        xUsernameSize > 0 && xUsernameSize <= usernameSize &&
        passwordSize > 0 && passwordSize <= unhashedPasswordSize,
    )

    user := database.FindUser(username, unhashedPassword)
    if user == nil {
        sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
        finishRequested(connectionId)
        return flagFinishWithError
    }

    setUser(connectionId, user)
    setConnectionState(connectionId, stateLoggedWithCredentials)

    token := crypto.MakeToken(connectionId, user.Id) // won't compile if inline the variable
    sendMessage(connectionId, serverMessage(flagLoggedIn, user.Id, token[:])) // here's how a client obtains his id
    return flagProceed
}

func registrationWithCredentialsRequested(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)

    if database.GetUsersCount() >= MaxUsersCount {
        sendMessage(connectionId, simpleServerMessage(flagError, toAnonymous))
        finishRequested(connectionId)
        return flagFinishWithError
    }

    username, unhashedPassword := parseCredentials(msg)
    user := database.AddUser(username, crypto.Hash(unhashedPassword))
    successful := user != nil

    sendMessage(connectionId, simpleServerMessage( // Lack of ternary operator is awful
        func() int32 { if successful { return flagRegistered } else { return flagError } }(),
        func() uint32 { if successful { return user.Id } else { return toAnonymous } }(),
    ))

    finishRequested(connectionId)
    if successful { return flagFinishToReconnect } else { return flagFinishWithError }
}

func finishRequested(connectionId uint32) int32 {
    deleteConnection(connectionId)
    return flagFinish
}

//goland:noinspection GoRedundantConversion
func usersListRequested(connectionId uint32, userId uint32) int32 {
    registeredUsers := database.GetAllUsers()
    var userInfosBytes []byte

    infosPerMessage := uint32(messageBodySize / userInfoSize)
    utils.Assert(infosPerMessage <= uint32(messageBodySize))
    stubBytes := make([]byte, uint32(messageBodySize) - infosPerMessage * uint32(userInfoSize))

    var infosCount uint32 = 0
    for _, user := range registeredUsers {
        _, xUser := findConnectUser(user.Id)

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

    return flagProceed
}

func routeMessage(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)
    flag := msg.flag
    xConnectionId, userIdFromToken := crypto.OpenToken(msg.token)

    state := getConnectionState(connectionId)
    utils.Assert(state != nil)
    userId := getConnectedUserId(connectionId)

    if flag == flagLogIn || flag == flagRegister {
        utils.Assert( // TODO: it fails again!
            *state == 0 && // state associated with this connectionId exist yet (non-existent map entry defaults to typed zero value)
            msg.from == fromAnonymous &&
            xConnectionId == nil &&
            userIdFromToken == nil &&
            msg.to == toServer,
        )

        setConnectionState(connectionId,stateSecureConnectionEstablished)
    } else {
        utils.Assert(
            *state > 0 &&
            userId != nil &&
            msg.from != fromAnonymous &&
            msg.from != fromServer,
        )

        if xConnectionId == nil || userIdFromToken == nil || *xConnectionId != connectionId || *userIdFromToken != *userId {
            sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
            finishRequested(connectionId)
            return flagFinishWithError
        }
    }

    switch flag {
        case flagShutdown:
            return shutdownRequested(connectionId, getUser(connectionId), msg)
        case flagProceed:
            return proceedRequested(msg)
        case flagLogIn:
            return loggingInWithCredentialsRequested(connectionId, msg)
        case flagRegister:
            return registrationWithCredentialsRequested(connectionId, msg)
        case flagFinish:
            utils.Assert(msg.to == toServer)
            return finishRequested(connectionId)
        case flagFetchUsers:
            return usersListRequested(connectionId, *userIdFromToken)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func onConnectionClosed(connectionId uint32) { finishRequested(connectionId) }
