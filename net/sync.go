
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
const flagAccessDenied int32 = 0x0000000b
const flagFetchUsers int32 = 0x0000000c
const flagShutdown int32 = 0x7fffffff

const toAnonymous uint32 = 0x7fffffff
const toServer uint32 = 0x7ffffffe

const stateSecureConnectionEstablished uint = 1
const stateLoggedWithCredentials uint = 2

const usernameSize uint = 16
const unhashedPasswordSize uint = 16

const fromAnonymous uint32 = 0xffffffff
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

var connectedUsers = make(map[uint32]*database.User) // key is connectionId
var connectionStates = make(map[uint32]uint) // map[connectionId]state

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
    utils.Assert(bodySize > 0 && bodySize <= int(messageBodySize))

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

    copy(unsafe.Slice(&(result.body[0]), messageBodySize), xBody)
    return result
}

func shutdownRequested(connectionId uint32, user *database.User, msg *message) int32 {
    utils.Assert(user != nil && msg.to == toServer)
    if database.IsAdmin(user) { return flagShutdown }
    sendMessage(connectionId, simpleServerMessage(flagAccessDenied, user.Id))
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

    connectedUsers[connectionId] = user
    connectionStates[connectionId] = stateLoggedWithCredentials

    token := makeToken(connectionId, user.Id) // won't compile if inline the variable
    sendMessage(connectionId, serverMessage(flagLoggedIn, user.Id, token[:])) // here's how a client obtains his id
    return flagProceed
}

func registrationWithCredentialsRequested(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)

    if len(database.GetAllUsers()) >= int(maxUsersCount) {
        sendMessage(connectionId, simpleServerMessage(flagError, toAnonymous))
        return flagFinishWithError
    }

    username, unhashedPassword := parseCredentials(msg)
    user := database.AddUser(username, crypto.Hash(unhashedPassword))
    successful := user != nil

    sendMessage(connectionId, simpleServerMessage( // Lack of ternary operator is awful
        func() int32 { if successful { return flagRegistered } else { return flagError } }(),
        func() uint32 { if successful { return user.Id } else { return toAnonymous } }(),
    ))

    if successful { return flagFinishToReconnect } else { return flagFinishWithError }
}

func finishRequested(connectionId uint32) int32 {
    delete(connectedUsers, connectionId)
    delete(connectionStates, connectionId)
    return flagFinish
}

//goland:noinspection GoRedundantConversion
func usersListRequested(connectionId uint32, userId uint32) int32 {
    registeredUsers := database.GetAllUsers()
    var userInfosBytes []byte

    var counter uint32 = 0
    for _, user := range registeredUsers {
        _, xUser := findConnectUsr(user.Id)

        xUserInfo := &userInfo{
            id: user.Id,
            connected: xUser != nil,
            name: [16]byte{},
        }
        copy(unsafe.Slice((*byte) (unsafe.Pointer(&(xUserInfo.name))), usernameSize), user.Name)

        userInfosBytes = append(userInfosBytes, xUserInfo.pack()...)
        counter++
    }
    utils.Assert(counter > 0 && counter <= uint32(maxUsersCount) && counter * uint32(userInfoSize) <= uint32(messageBodySize - intSize))

    userInfoBytesSize := len(userInfosBytes)
    utils.Assert(userInfoBytesSize <= int(messageBodySize))
    bytes := make([]byte, intSize + userInfoBytesSize)

    copy(bytes, unsafe.Slice((*byte) (unsafe.Pointer(&counter)), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), userInfoBytesSize), userInfosBytes)

    sendMessage(connectionId, serverMessage(flagFetchUsers, userId, bytes))
    return flagProceed
}

func routeMessage(connectionId uint32, msg *message) int32 {
    utils.Assert(msg != nil)
    flag := msg.flag
    xConnectionId, userId := openToken(msg.token)

    if flag == flagLogIn || flag == flagRegister {
        utils.Assert( //TODO: fails when trying to log in with correct credentials of the 'user1' after [successful logging in with those credentials and disconnecting after successful users list fetching] - possible issues with deleting the connectionId from map
            connectionStates[connectionId] == 0 && // state associated with this connectionId exist yet (non-existent map entry defaults to typed zero value)
            msg.from == fromAnonymous &&
            xConnectionId == nil &&
            userId == nil &&
            msg.to == toServer,
        )

        connectionStates[connectionId] = stateSecureConnectionEstablished
    } else {
        utils.Assert(
            connectionStates[connectionId] > 0 &&
            msg.from != fromAnonymous &&
            msg.from != fromServer,
        )

        if xConnectionId == nil || userId == nil || *xConnectionId != connectionId || *userId != connectedUsers[connectionId].Id {
            sendMessage(connectionId, simpleServerMessage(flagUnauthenticated, toAnonymous))
            finishRequested(connectionId)
            return flagFinishWithError
        }
    }

    switch flag {
        case flagShutdown:
            return shutdownRequested(connectionId, connectedUsers[connectionId], msg)
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
            return usersListRequested(connectionId, *userId)
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func findConnectUsr(userId uint32) (uint32, *database.User) { // nillable second result
    for i, j := range connectedUsers { if j.Id == userId { return i, j } }
    return 0, nil
}
