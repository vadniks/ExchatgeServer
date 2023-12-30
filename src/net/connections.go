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
	connection      *goNet.Conn
	crypto          *xCrypto.Crypto
	user            *database.User // nillable
	state           uint
	connectedMillis uint64
}

type connectionsT struct {
	connectedUsers map[uint32] /*connectionId*/ *connectedUser // nillable values
	ids            map[uint32] /*userId*/ *uint32              /*connectionId*/ // nillable values
	rwMutex        goSync.RWMutex
}

var connections = &connectionsT{
	make(map[uint32]*connectedUser),
	make(map[uint32]*uint32),
	goSync.RWMutex{},
}

func addNewConnection(connectionId uint32, connection *goNet.Conn, xxCrypto *xCrypto.Crypto) {
	connections.rwMutex.Lock()

	_, ok := connections.connectedUsers[connectionId]
	utils.Assert(!ok)

	connections.connectedUsers[connectionId] = &connectedUser{
		connection:      connection,
		crypto:          xxCrypto,
		user:            nil,
		state:           stateConnected,
		connectedMillis: utils.CurrentTimeMillis(),
	}

	connections.rwMutex.Unlock()
}

func getConnectedUser(connectionId uint32) *connectedUser { // nillable result
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

func getCrypto(connectionId uint32) *xCrypto.Crypto { // nillable result
	xConnectedUser := getConnectedUser(connectionId)
	if xConnectedUser == nil {
		return nil
	}
	return xConnectedUser.crypto
}

func getConnection(connectionId uint32) *goNet.Conn { // nillable result
	xConnectedUser := getConnectedUser(connectionId)
	if xConnectedUser == nil {
		return nil
	}
	return xConnectedUser.connection
}

func getConnectionState(connectionId uint32) *uint { // nillable result
	xConnectedUser := getConnectedUser(connectionId)
	if xConnectedUser == nil {
		return nil
	}
	return &(xConnectedUser.state)
}

func setConnectionState(connectionId uint32, state uint) bool { // returns true on success
	xConnectedUser := getConnectedUser(connectionId)
	if xConnectedUser == nil {
		return false
	}

	connections.rwMutex.Lock()
	xConnectedUser.state = state
	connections.rwMutex.Unlock()

	return true
}

func getUser(connectionId uint32) *database.User { // nillable result
	xConnectedUser := getConnectedUser(connectionId)
	if xConnectedUser == nil {
		return nil
	}
	return xConnectedUser.user
}

func setUser(connectionId uint32, user *database.User) bool { // returns true on success
	connectedUser := getConnectedUser(connectionId)
	if connectedUser == nil {
		return false
	}
	connections.rwMutex.Lock()

	connectedUser.user = user

	_, ok := connections.ids[user.Id]
	utils.Assert(!ok)

	xConnectionId := new(uint32)
	*xConnectionId = connectionId
	connections.ids[user.Id] = xConnectionId

	connections.rwMutex.Unlock()
	return true
}

func getConnectedUserId(connectionId uint32) *uint32 { // nillable result
	user := getUser(connectionId)
	if user == nil {
		return nil
	}
	return &(user.Id)
}

func getAuthorizedConnectedUser(userId uint32) (uint32, *database.User) { // nillable second result
	connections.rwMutex.RLock()
	connectionId := connections.ids[userId]

	if connectionId == nil {
		connections.rwMutex.RUnlock()
		return 0, nil
	}

	connectedUser, ok := connections.connectedUsers[*connectionId]
	connections.rwMutex.RUnlock()
	if !ok {
		return 0, nil
	}

	if user := connectedUser.user; user == nil {
		return 0, nil
	} else {
		return *connectionId, connectedUser.user
	}
}

func checkConnectionTimeouts(action func(connectionId uint32, xConnectedUser *connectedUser)) {
	connections.rwMutex.Lock()

	for connectionId, xConnectedUser := range connections.connectedUsers {
		if utils.CurrentTimeMillis()-xConnectedUser.connectedMillis > net.maxTimeMillisToPreserveActiveConnection {
			action(connectionId, xConnectedUser)
		}
	}

	connections.rwMutex.Unlock()
}

func deleteConnection(connectionId uint32) bool { // returns true on success
	connectedUser := getConnectedUser(connectionId)
	if connectedUser == nil {
		return false
	}

	connections.rwMutex.Lock()

	delete(connections.connectedUsers, connectionId)
	if user := connectedUser.user; user != nil {
		delete(connections.ids, user.Id)
	}

	connections.rwMutex.Unlock()
	return true
}
