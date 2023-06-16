
package net

import (
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
)

const flagProceed int32 = 0x00000000
const flagFinish int32 = 0x00000001
const flagFetchAll int32 = 0x00000002
const flagUsername int32 = 0x00000003
const flagPassword int32 = 0x00000004
const flagAuthenticated int32 = 0x00000005
const flagUnauthenticated int32 = 0x00000006
const flagRegister int32 = 0x00000007
const flagRegisterSucceeded int32 = 0x00000008
const flagRegisterFailed int32 = 0x00000009
const flagId int32 = 0x0000000a
const flagAdminShutdown int32 = 0x7fffffff

const fromServer uint32 = 0x7fffffff

var connectedUsers map[uint]*database.User // key is connectionId

func syncMessage(connectionId uint, msg *message) int32 {
    flag := msg.flag
    usr := connectedUsers[connectionId]

    switch flag {
        case flagAdminShutdown:
            if database.IsAdmin(usr) {
                return flagAdminShutdown
            } else {
                sendMessage(connectionId, &message{
                    flag: flagUnauthenticated,
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
        case flagProceed:
            if toUserConnectionId, toUser := findConnectUsr(msg.to); toUser != nil {
                sendMessage(toUserConnectionId, msg)
            } else {
                // TODO: user offline or doesn't exist
            }
            break
        default:
            utils.JustThrow()
    }
    return 0 // not gonna get here
}

func findConnectUsr(userId uint32) (uint, *database.User) { // nillable second result
    for i, j := range connectedUsers { if j.Id == userId { return i, j } }
    return 0, nil
}
