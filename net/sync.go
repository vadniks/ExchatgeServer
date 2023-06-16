
package net

import "ExchatgeServer/database"

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

var connectedUsers map[uint]*database.User

func syncMessage(connectionId uint, msg *message) int32 {
    flag := msg.flag

    if flag == flagAdminShutdown {
        if database.IsAdmin(connectedUsers[connectionId]) {
            return flagAdminShutdown
        } else {
            // TODO: not an admin
        }
    }

    return flag
}
