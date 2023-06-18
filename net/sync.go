
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
const flagLogIn int32 = 0x00000004
const flagLoggedIn int32 = 0x00000005
const flagRegister int32 = 0x00000006
const flagRegistered int32 = 0x00000007
const flagSuccess int32 = 0x00000008
const flagError int32 = 0x00000009
const flagUnauthenticated int32 = 0x0000000a
const flagFetchAll int32 = 0x0000000b // TODO: add messages fetching mechanism
const flagShutdown int32 = 0x7fffffff

const toAnonymous uint32 = 0x7fffffff

const stateSecureConnectionEstablished uint = 1
const stateLoggedWithCredentials uint = 2

const usernameSize uint = 16
const unhashedPasswordSize uint = 16

const fromAnonymous uint32 = 0x00000000
const fromServer uint32 = 0x7fffffff

var tokenAnonymous = make([]byte, tokenSize) // all zeroes

var tokenServer = func() [tokenSize]byte { // letting clients to verify server's signature
    //goland:noinspection GoBoolExpressions - just to make sure
    utils.Assert(tokenSize == crypto.SignatureSize)

    unsigned := make([]byte, tokenUnencryptedValueSize)
    for i, _ := range unsigned { unsigned[i] = (1 << 8) - 1 } // 255

    signed := crypto.Sign(unsigned)
    utils.Assert(len(signed) - tokenUnencryptedValueSize == int(crypto.SignatureSize))

    var arr [tokenSize]byte
    copy(unsafe.Slice(&(arr[0]), messageBodySize), signed[:crypto.SignatureSize]) // only signature goes into token as clients know what's the signed constant value is

    return arr
}()

var bodyStub = [messageBodySize]byte{} // all zeroes

var connectedUsers map[uint32]*database.User // key is connectionId
var connectionStates map[uint32]uint // map[connectionId]state

func simpleServerMessage(xFlag int32, xTo uint32) *message {
    return &message{
        flag: xFlag,
        timestamp: utils.CurrentTimeMillis(),
        size: 0,
        index: 0,
        count: 1,
        from: fromServer,
        to: xTo,
        token: tokenServer,
        body: bodyStub,
    }
}

func serverMessage(xFlag int32, xTo uint32, xBody []byte) *message {
    bodySize := len(xBody)
    maxBodySize := messageBodySize - crypto.SignatureSize
    utils.Assert(bodySize > 0 && bodySize <= int(maxBodySize))

    signedBody := crypto.Sign(xBody)
    utils.Assert(len(signedBody) == int(messageBodySize))

    result := &message{
        flag: xFlag,
        timestamp: utils.CurrentTimeMillis(),
        size: uint32(bodySize),
        index: 0,
        count: 1,
        from: fromServer,
        to: xTo,
        token: tokenServer,
    }

    copy(unsafe.Slice(&(result.body[0]), messageBodySize), signedBody)
    return result
}

func shutdownRequested(connectionId uint32, user *database.User) int32 {
    utils.Assert(user != nil)
    if database.IsAdmin(user) { return flagShutdown }

    sendMessage(connectionId, simpleServerMessage(flagError, user.Id))
    return flagProceed
}

//goland:noinspection GoRedundantConversion (*byte) - just silence that annoying warning already!
func proceedRequested(msg *message) int32 {
    utils.Assert(msg != nil)

    if toUserConnectionId, toUser := findConnectUsr(msg.to); toUser != nil {
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

    unhashedPassword = make([]byte, crypto.HashSize)
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

    connectedUsers[connectionId] = user
    connectionStates[connectionId] = stateLoggedWithCredentials

    token := makeToken(connectionId, user.Id) // won't compile if inline the variable
    sendMessage(connectionId, serverMessage(flagLoggedIn, toAnonymous, token[:])) // here's how a client obtains his id
    return flagProceed
}

func registrationWithCredentialsRequested(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)

    username, unhashedPassword := parseCredentials(msg)
    user := database.AddUser(username, crypto.Hash(unhashedPassword))
    successful := user != nil

    sendMessage(connectionId, simpleServerMessage( // Lack of ternary operator is awful
        func() int32 { if successful { return flagRegistered } else { return flagError } }(),
        func() uint32 { if successful { return user.Id } else { return toAnonymous } }(),
    ))

    if successful { return flagFinishToReconnect } else { return flagError }
}

func finishRequested(connectionId uint32) int32 {
    delete(connectedUsers, connectionId)
    delete(connectionStates, connectionId)
    return flagFinish
}

func routeMessage(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)
    flag := msg.flag
    xConnectionId, userId := openToken(msg.token)

    if flag == flagLogIn || flag == flagRegister {
        utils.Assert(
            connectionStates[connectionId] == 0 && // state associated with this connectionId exist yet (non-existent map entry defaults to typed zero value)
            msg.from == fromAnonymous &&
            xConnectionId == nil &&
            userId == nil,
        )

        connectionStates[connectionId] = stateSecureConnectionEstablished
    } else {
        utils.Assert(
            connectionStates[connectionId] > 0 &&
            msg.from != fromAnonymous &&
            msg.from != fromServer,
        )

        if xConnectionId == nil || userId == nil || *xConnectionId != connectionId {
            sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
            finishRequested(connectionId)
            return flagFinishWithError
        }
    }

    switch flag {
        case flagShutdown:
            return shutdownRequested(connectionId, connectedUsers[connectionId])
        case flagProceed:
            return proceedRequested(msg)
        case flagLogIn:
            return loggingInWithCredentialsRequested(connectionId, msg)
        case flagRegister:
            return registrationWithCredentialsRequested(connectionId, msg)
        case flagFinish:
            return finishRequested(connectionId)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func findConnectUsr(userId uint32) (uint32, *database.User) { // nillable second result
    for i, j := range connectedUsers { if j.Id == userId { return i, j } }
    return 0, nil
}
