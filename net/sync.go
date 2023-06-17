
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
const flagLoginWithCredentials int32 = 0x00000003
const flagLoggedIn int32 = 0x00000004
const flagRegisterWithCredentials int32 = 0x00000005
const flagRegistered int32 = 0x00000006
const flagSuccess int32 = 0x00000007
const flagError int32 = 0x00000008
const flagId int32 = 0x00000009
const flagFetchAll int32 = 0x0000000a
const flagShutdown int32 = 0x7fffffff

const fromServer uint32 = 0x7fffffff // TODO: sign messages from server & check signature on client side

const stateSecureConnectionEstablished = 0
const stateLoggedWithCredentials = 1
const stateRegisteredWithCredentials = 2 // TODO: deal with registration in the context of connection-related finite state machine
const stateFinishedNormally = 3
const stateFinishedWithError = 4

const usernameSize uint = 16

var connectedUsers map[uint]*database.User // key is connectionId
var connectionStates map[uint]uint // map[connectionId]state

var fromServerMessageBodyStub = func() [messageBodySize]byte {
    signed := crypto.Sign(make([]byte, messageBodySize - crypto.SignatureSize))
    var arr [messageBodySize]byte
    copy(unsafe.Slice(&(arr[0]), messageBodySize), signed)
    return arr
}()

func shutdownRequested(connectionId uint, usr *database.User) int32 {
    utils.Assert(usr != nil)

    if database.IsAdmin(usr) {
        return flagShutdown
    } else {
        sendMessage(connectionId, &message{
            flag: flagError,
            timestamp: utils.CurrentTimeMillis(),
            size: 0,
            index: 0,
            count: 1,
            from: fromServer,
            to: usr.Id,
            body: fromServerMessageBodyStub,
        })
        return flagProceed
    }
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

func parseCredentials(msg *message) (username []byte, passwordHash []byte) {
    utils.Assert(msg != nil && (msg.flag == flagLoginWithCredentials || msg.flag == flagRegisterWithCredentials))

    username = make([]byte, usernameSize)
    copy(username, unsafe.Slice(&(msg.body[0]), usernameSize))

    passwordHash = make([]byte, crypto.HashSize)
    copy(passwordHash, unsafe.Slice(&(msg.body[usernameSize]), crypto.HashSize))

    return username, passwordHash
}

func loginWithCredentialsRequested(connectionId uint, msg *message) int32 {
    utils.Assert(msg != nil)

    username, passwordHash := parseCredentials(msg)
    userId := database.CheckUser(&database.User{
        Name: username,
        Password: passwordHash,
    })

    if userId != nil {
        connectionStates[connectionId] = stateLoggedWithCredentials
        sendMessage(connectionId, &message{
            flag: flagLoggedIn,
            timestamp: utils.CurrentTimeMillis(),
            size: 0,
            index: 0,
            count: 0,
            from: fromServer,
            to: *userId, // here's how a client obtains his id
            body: fromServerMessageBodyStub,
        })
        return flagProceed
    } else {
        connectionStates[connectionId] = stateFinishedWithError
        return flagFinishWithError
    }
}

func syncMessage(connectionId uint, msg *message) int32 {
    utils.Assert(msg != nil)

    flag := msg.flag
    usr := connectedUsers[connectionId]
    connectionStates[connectionId] = stateSecureConnectionEstablished

    switch flag {
        case flagShutdown:
            return shutdownRequested(connectionId, usr)
        case flagProceed:
            return proceedRequested(msg)
        case flagLoginWithCredentials:
            return loginWithCredentialsRequested(connectionId, msg)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func findConnectUsr(userId uint32) (uint, *database.User) { // nillable second result
    for i, j := range connectedUsers { if j.Id == userId { return i, j } }
    return 0, nil
}
