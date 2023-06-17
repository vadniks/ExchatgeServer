
package net

import (
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
)

const flagProceed int32 = 0x00000000
const flagFinish int32 = 0x00000001
const flagFetchAll int32 = 0x00000002
const flagLoginWithCredentials int32 = 0x00000003
const flagRegisterWithCredentials int32 = 0x00000004
const flagError int32 = 0x00000005
const flagId int32 = 0x00000006
const flagShutdown int32 = 0x7fffffff

const fromServer uint32 = 0x7fffffff // TODO: sign messages from server & check signature on client side

const stateSecureConnectionEstablished = 0
const stateLoggedWithCredentials = 1
const stateRegisteredWithCredentials = 2 // TODO: deal with registration in the context of connection-related finite state machine
const stateFinishedNormally = 3
const stateFinishedWithError = 4

var connectedUsers map[uint]*database.User // key is connectionId
var connectionStates map[uint]uint // map[connectionId]state

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
            body: [1024]byte{},
        })
        return flagProceed
    }
}

func sendMessageToReceiver(msg *message) int32 {
    utils.Assert(msg != nil)

    if toUserConnectionId, toUser := findConnectUsr(msg.to); toUser != nil {
        sendMessage(toUserConnectionId, msg)
    } else {
        // TODO: user offline or doesn't exist
    }
    return flagProceed
}

func parseCredentials(msg *message) (username []byte, passwordHash []byte) {
    utils.Assert(msg != nil)
    return []byte{}, []byte{} // TODO
}

func loginWithCredentialsRequested(connectionId uint, msg *message) int32 {
    utils.Assert(msg != nil)

    // TODO message body size = 1024, hashed size = 128, so: 16 bytes for username and 128 bytes for hashed password = 144 bytes for credentials
    if true {
        // TODO: password correct
        connectionStates[connectionId] = stateLoggedWithCredentials
        return flagProceed
    } else {
        // TODO: password incorrect
        connectionStates[connectionId] = stateFinishedWithError
        return flagFinish
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
            return sendMessageToReceiver(msg)
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
