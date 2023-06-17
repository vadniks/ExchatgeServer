
package net

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    "unsafe"
)

const flagProceed int32 = 0x00000000
const flagFinish int32 = 0x00000001
const flagFinishWithError int32 = 0x00000002
const flagFinishToReconnect int32 = 0x00000003 // after registration connection closes and client should reconnect & login
const flagLoginWithCredentials int32 = 0x00000004
const flagLoggedIn int32 = 0x00000005
const flagRegisterWithCredentials int32 = 0x00000006
const flagRegistered int32 = 0x00000007
const flagSuccess int32 = 0x00000008
const flagError int32 = 0x00000009
const flagId int32 = 0x0000000a
const flagFetchAll int32 = 0x0000000b // TODO: add messages fetching mechanism
const flagShutdown int32 = 0x7fffffff

const fromServer uint32 = 0x7fffffff
const toAnonymous uint32 = 0x7fffffff

const stateSecureConnectionEstablished = 0
const stateLoggedWithCredentials = 1

const usernameSize uint = 16
const unhashedPasswordSize uint = 16

var connectedUsers map[uint]*database.User // key is connectionId
var connectionStates map[uint]uint // map[connectionId]state

var fromServerMessageBodyStub = func() [messageBodySize]byte { // letting clients to verify server's signature
    signed := crypto.Sign(make([]byte, messageBodySize - crypto.SignatureSize))
    var arr [messageBodySize]byte
    copy(unsafe.Slice(&(arr[0]), messageBodySize), signed)
    return arr
}()

func shutdownRequested(connectionId uint, usr *database.User) int32 {
    utils.Assert(usr != nil)
    if database.IsAdmin(usr) { return flagShutdown }

    sendMessage(connectionId, &message{
        flag: flagError,
        timestamp: utils.CurrentTimeMillis(),
        size: messageBodySize,
        index: 0,
        count: 1,
        from: fromServer,
        to: usr.Id,
        body: fromServerMessageBodyStub,
    })
    return flagProceed
}

func proceedRequested(msg *message) int32 {
    utils.Assert(msg != nil)

    if toUserConnectionId, toUser := findConnectUsr(msg.to); toUser != nil {
        sendMessage(toUserConnectionId, msg)
    } else {
        // TODO: user offline or doesn't exist
    }
    return flagProceed
}

func parseCredentials(msg *message) (username []byte, unhashedPassword []byte) {
    utils.Assert(msg != nil && (msg.flag == flagLoginWithCredentials || msg.flag == flagRegisterWithCredentials))

    username = make([]byte, usernameSize)
    copy(username, unsafe.Slice(&(msg.body[0]), usernameSize))

    unhashedPassword = make([]byte, crypto.HashSize)
    copy(unhashedPassword, unsafe.Slice(&(msg.body[usernameSize]), crypto.HashSize))

    return username, unhashedPassword
}

func loggingInWithCredentialsRequested(connectionId uint, msg *message) int32 { // expects the password not to be hashed in order to compare it with salted hash (which is always different)
    utils.Assert(msg != nil)

    username, unhashedPassword := parseCredentials(msg)

    xUsernameSize := uint(len(username)); passwordSize := uint(len(unhashedPassword))
    utils.Assert(
        xUsernameSize > 0 && xUsernameSize <= usernameSize &&
        passwordSize > 0 && passwordSize <= unhashedPasswordSize,
    )

    user := database.FindUser(username, unhashedPassword)
    if user == nil {
        sendMessage(connectionId, &message{
            flag: flagError,
            timestamp: utils.CurrentTimeMillis(),
            size: messageBodySize,
            index: 0,
            count: 1,
            from: fromServer,
            to: toAnonymous,
            body: fromServerMessageBodyStub,
        })

        delete(connectionStates, connectionId)
        return flagFinishWithError
    }

    connectedUsers[connectionId] = user
    connectionStates[connectionId] = stateLoggedWithCredentials

    sendMessage(connectionId, &message{
        flag: flagLoggedIn,
        timestamp: utils.CurrentTimeMillis(),
        size: messageBodySize,
        index: 0,
        count: 1,
        from: fromServer,
        to: user.Id, // here's how a client obtains his id
        body: fromServerMessageBodyStub,
    })
    return flagProceed
}

func registrationWithCredentialsRequested(connectionId uint, msg *message) int32 {
    utils.Assert(msg != nil)

    username, unhashedPassword := parseCredentials(msg)
    user := database.AddUser(username, crypto.Hash(unhashedPassword))
    successful := user != nil

    sendMessage(connectionId, &message{
        flag: func() int32 { if successful { return flagRegistered } else { return flagError } }(),
        timestamp: utils.CurrentTimeMillis(),
        size: messageBodySize,
        index: 0,
        count: 1,
        from: fromServer,
        to: func() uint32 { if successful { return user.Id } else { return toAnonymous } }(),
        body: fromServerMessageBodyStub,
    })

    if successful { return flagFinishToReconnect } else { return flagError }
}

func finishRequested(connectionId uint) int32 {
    delete(connectedUsers, connectionId)
    delete(connectionStates, connectionId)
    return flagFinish
}

func syncMessage(connectionId uint, msg *message) int32 { // TODO: rename to routeMessage or smth
    utils.Assert(msg != nil)
    connectionStates[connectionId] = stateSecureConnectionEstablished // TODO: test all

    switch msg.flag {
        case flagShutdown:
            return shutdownRequested(connectionId, connectedUsers[connectionId])
        case flagProceed:
            return proceedRequested(msg)
        case flagLoginWithCredentials:
            return loggingInWithCredentialsRequested(connectionId, msg)
        case flagRegisterWithCredentials:
            return registrationWithCredentialsRequested(connectionId, msg)
        case flagFinish:
            return finishRequested(connectionId)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func findConnectUsr(userId uint32) (uint, *database.User) { // nillable second result
    for i, j := range connectedUsers { if j.Id == userId { return i, j } }
    return 0, nil
}
