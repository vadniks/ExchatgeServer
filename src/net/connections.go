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
    xCrypto "ExchatgeServer/crypto"
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    goNet "net"
    goSync "sync"
)

type connectedUser struct {
    connection *goNet.Conn
    crypto *xCrypto.Crypto
    user *database.User // nillable
    state uint
}

type connectionsT struct {
    connectedUsers map[uint32/*connectionId*/]*connectedUser // nillable values
    ids map[uint32/*userId*/]*uint32/*connectionId*/ // nillable values
    mutex goSync.Mutex
}
var connections = &connectionsT{
    make(map[uint32]*connectedUser),
    make(map[uint32]*uint32),
    goSync.Mutex{},
}

func addNewConnection(connectionId uint32, connection *goNet.Conn, xxCrypto *xCrypto.Crypto) {
    connections.mutex.Lock()

    _, ok := connections.connectedUsers[connectionId]
    utils.Assert(!ok)

    connections.connectedUsers[connectionId] = &connectedUser{
        connection: connection,
        crypto: xxCrypto,
        user: nil,
        state: stateConnected,
    }

    connections.mutex.Unlock()
}

func getConnectedUser(connectionId uint32) *connectedUser { // nillable result
    connections.mutex.Lock()
    value, ok := connections.connectedUsers[connectionId]
    connections.mutex.Unlock()

    if ok {
        utils.Assert(value != nil)
        return value
    } else {
        return nil
    }
}

func getCrypto(connectionId uint32) *xCrypto.Crypto { // nillable result
    xConnectedUser := getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.crypto
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
    connectedUser := getConnectedUser(connectionId)
    if connectedUser == nil { return false }
    connections.mutex.Lock()

    connectedUser.user = user

    _, ok := connections.ids[user.Id]
    utils.Assert(!ok)

    xConnectionId := new(uint32)
    *xConnectionId = connectionId
    connections.ids[user.Id] = xConnectionId

    connections.mutex.Unlock()
    return true
}

func getConnectedUserId(connectionId uint32) *uint32 { // nillable result
    user := getUser(connectionId)
    if user == nil { return nil }
    return &(user.Id)
}

func getAuthorizedConnectedUser(userId uint32) (uint32, *database.User) { // nillable second result
    connections.mutex.Lock()
    connectionId := connections.ids[userId]
    connections.mutex.Unlock()

    if connectionId == nil { return 0, nil }

    connectedUser, ok := connections.connectedUsers[*connectionId]
    if !ok { return 0, nil }

    if user := connectedUser.user; user == nil {
        return 0, nil
    } else {
        return *connectionId, connectedUser.user
    }
}

func deleteConnection(connectionId uint32) bool { // returns true on success
    connectedUser := getConnectedUser(connectionId)
    if connectedUser == nil { return false }

    connections.mutex.Lock()

    delete(connections.connectedUsers, connectionId)
    if user := connectedUser.user; user != nil { delete(connections.ids, user.Id) }

    connections.mutex.Unlock()
    return true
}
