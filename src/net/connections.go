/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023-2024  Vadim Nikolaev (https://github.com/vadniks)
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
    "ExchatgeServer/crypto"
    "ExchatgeServer/database"
    "ExchatgeServer/utils"
    goNet "net"
    goSync "sync"
)

type connectedUser struct {
    connection *goNet.Conn
    coders *crypto.Coders
    user *database.User // nillable
    state uint
    connectedMillis uint64
}

type connectionsT struct {
    connectedUsers map[uint32/*connectionId*/]*connectedUser // nillable values
    ids map[uint32/*userId*/]*uint32/*connectionId*/ // nillable values
    rwMutex goSync.RWMutex
}
var connections = &connectionsT{ // aka singleton
   make(map[uint32]*connectedUser),
   make(map[uint32]*uint32),
   goSync.RWMutex{},
}

func (connections *connectionsT) addNewConnection(connectionId uint32, connection *goNet.Conn, coders *crypto.Coders) {
    connections.rwMutex.Lock()

    _, ok := connections.connectedUsers[connectionId]
    utils.Assert(!ok)

    connections.connectedUsers[connectionId] = &connectedUser{
        connection: connection,
        coders: coders,
        user: nil,
        state: stateConnected,
        connectedMillis: utils.CurrentTimeMillis(),
    }

    connections.rwMutex.Unlock()
}

func (connections *connectionsT) getConnectedUser(connectionId uint32) *connectedUser { // nillable result
    connections.rwMutex.RLock()
    value, ok := connections.connectedUsers[connectionId]
    connections.rwMutex.RUnlock()

    if ok {
        utils.Assert(value != nil)
        return value
    } else {
        return nil
    }
}

func (connections *connectionsT) getCoders(connectionId uint32) *crypto.Coders { // nillable result
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.coders
}

func (connections *connectionsT) getConnection(connectionId uint32) *goNet.Conn { // nillable result
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.connection
}

func (connections *connectionsT) getConnectionState(connectionId uint32) *uint { // nillable result
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return &(xConnectedUser.state)
}

func (connections *connectionsT) setConnectionState(connectionId uint32, state uint) bool { // returns true on success
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return false }

    connections.rwMutex.Lock()
    xConnectedUser.state = state
    connections.rwMutex.Unlock()

    return true
}

func (connections *connectionsT) getUser(connectionId uint32) *database.User { // nillable result
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return nil }
    return xConnectedUser.user
}

func (connections *connectionsT) setUser(connectionId uint32, user *database.User) bool { // returns true on success
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return false }
    connections.rwMutex.Lock()

    xConnectedUser.user = user

    _, ok := connections.ids[user.Id]
    utils.Assert(!ok)

    xConnectionId := new(uint32)
    *xConnectionId = connectionId
    connections.ids[user.Id] = xConnectionId

    connections.rwMutex.Unlock()
    return true
}

func (connections *connectionsT) getConnectedUserId(connectionId uint32) *uint32 { // nillable result
    user := connections.getUser(connectionId)
    if user == nil { return nil }
    return &(user.Id)
}

func (connections *connectionsT) getAuthorizedConnectedUser(userId uint32) (uint32, *database.User) { // nillable second result
    connections.rwMutex.RLock()
    connectionId := connections.ids[userId]

    if connectionId == nil {
        connections.rwMutex.RUnlock()
        return 0, nil
    }

    xConnectedUser, ok := connections.connectedUsers[*connectionId]
    connections.rwMutex.RUnlock()
    if !ok { return 0, nil }

    if user := xConnectedUser.user; user == nil {
        return 0, nil
    } else {
        return *connectionId, xConnectedUser.user
    }
}

func (connections *connectionsT) checkConnectionTimeouts(action func(xConnectedUser *connectedUser)) {
    connections.rwMutex.Lock()

    for _, xConnectedUser := range connections.connectedUsers {
        if utils.CurrentTimeMillis() - xConnectedUser.connectedMillis > Net.maxTimeMillisToPreserveActiveConnection {
            action(xConnectedUser)
        }
    }

    connections.rwMutex.Unlock()
}

func (connections *connectionsT) doForEachConnectedAuthorizedUser(action func (connectionId uint32, user *connectedUser)) {
    connections.rwMutex.RLock()

    for connectionId, xConnectedUser := range connections.connectedUsers {
        if xConnectedUser.user != nil { action(connectionId, xConnectedUser) }
    }

    connections.rwMutex.RUnlock()
}

func (connections *connectionsT) deleteConnection(connectionId uint32) bool { // returns true on success
    xConnectedUser := connections.getConnectedUser(connectionId)
    if xConnectedUser == nil { return false }

    connections.rwMutex.Lock()

    delete(connections.connectedUsers, connectionId)
    if user := xConnectedUser.user; user != nil { delete(connections.ids, user.Id) }

    connections.rwMutex.Unlock()
    return true
}
