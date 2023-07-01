
package net

import (
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    goNet "net"
)

type connectedUser struct {
    connection *goNet.Conn
    encryptionKey []byte
    user *database.User // nillable
    state uint
}
var connectedUsers = make(map[uint32/*connectionId*/]*connectedUser) // nillable values

func addNewConnection(connectionId uint32, connection *goNet.Conn, encryptionKey []byte) {
    connectedUsers[connectionId] = &connectedUser{
        connection: connection,
        encryptionKey: encryptionKey,
        user: nil,
        state: stateConnected,
    }
}

func getConnectedUser(connectionId uint32) *connectedUser { // nillable result
    value, ok := connectedUsers[connectionId]
    if ok {
        utils.Assert(value != nil)
        return value
    } else {
        return nil
    }
}

func getEncryptionKey(connectionId uint32) []byte { // nillable result
    xConnectedUser := getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.encryptionKey
}

func getConnection(connectionId uint32) *goNet.Conn { // nillable result
    xConnectedUser := getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.connection
}

func getConnectionState(connectionId uint32) *uint { // nillable result
    xConnectedUser := getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return &(xConnectedUser.state)
}

func setConnectionState(connectionId uint32, state uint) bool { // returns true on success
    if xConnectedUser := getConnectedUser(connectionId); xConnectedUser != nil {
        xConnectedUser.state = state
        return true
    } else {
        return false
    }
}

func getUser(connectionId uint32) *database.User { // nillable result
    xConnectedUser := getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.user
}

func setUser(connectionId uint32, user *database.User) bool { // returns true on success
    if xConnectedUser := getConnectedUser(connectionId); xConnectedUser != nil {
        xConnectedUser.user = user
        return true
    } else {
        return false
    }
}

func getConnectedUserId(connectionId uint32) *uint32 { // nillable result
    user := getUser(connectionId)
    if user == nil { return nil }
    return &(user.Id)
}

func deleteConnection(connectionId uint32) bool { // returns true on success
    if xConnectedUser := getConnectedUser(connectionId); xConnectedUser != nil {
        delete(connectedUsers, connectionId)
        return true
    } else {
        return false
    }
}
