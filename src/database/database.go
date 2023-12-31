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

package database

import (
    "ExchatgeServer/crypto"
    xIdsPool "ExchatgeServer/idsPool"
    "ExchatgeServer/utils"
    "context"
    "errors"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "reflect"
    "strings"
    "sync"
)

const databaseName = "admin"
const collectionUsers = "users"
const collectionMessages = "messages"

const fieldRealId = "_id"
const fieldId = "id"
const fieldName = "name"
const fieldPassword = "password"

const fieldTimestamp = "timestamp"
const fieldFrom = "from"
const fieldTo = "to"
const fieldBody = "body"

type User struct {
    Id uint32 `bson:"id"`
    Name []byte `bson:"name"`
    Password []byte `bson:"password"` // salty-hashed
}

type Message struct {
    Timestamp uint64 `bson:"timestamp"`
    From uint32 `bson:"from"`
    To uint32 `bson:"to"`
    Body []byte `bson:"body"`
}

func (user *User) passwordHashed() *User {
    user.Password = crypto.Hash(user.Password)
    return user
}

type database struct {
    ctx *context.Context
    users *mongo.Collection
    messages *mongo.Collection
    client *mongo.Client
    adminUsername []byte
    adminPassword []byte
    idsPool *xIdsPool.IdsPool
    rwMutex sync.RWMutex
}
var this *database = nil

func Initialize(maxUsersCount uint32, mongoUrl string, adminPassword []byte) {
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    this = &database{
        &ctx,
        client.Database(databaseName).Collection(collectionUsers),
        client.Database(databaseName).Collection(collectionMessages),
        client,
        []byte{'a', 'd', 'm', 'i', 'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        crypto.Hash(adminPassword),
        xIdsPool.InitIdsPool(maxUsersCount),
        sync.RWMutex{},
    }

    for i := range adminPassword { adminPassword[i] = 0 }

    addAdminIfNotExists()
    mocData() // TODO: test only
    loadIds()
}

func loadIds() {
    for _, i := range GetAllUsers() {
        this.idsPool.SetId(i.Id, true)
    }
}

func Destroy() {
    this.rwMutex.Lock()
    result := this.client.Database(databaseName).RunCommand(*(this.ctx), bson.D{{"shutdown", 1}})

    utils.Assert(
        result != nil &&
        result.Err() != nil &&
        strings.Contains(result.Err().Error(), "socket was unexpectedly closed: EOF"),
    )

    utils.Assert(this.client.Disconnect(*(this.ctx)) == nil)
    this.rwMutex.Unlock()
}

func addAdminIfNotExists() { // admin is the only user that has id equal to 0
    id := availableUserId()
    utils.Assert(id != nil && *id == uint32(0))

    if result := this.users.FindOne(
        *(this.ctx),
        bson.D{{fieldId, 0}, {fieldName, this.adminUsername}},
    ); errors.Is(result.Err(), mongo.ErrNoDocuments) {
        _, err := this.users.InsertOne(*(this.ctx), User{Id: *id, Name: this.adminUsername, Password: this.adminPassword})
        utils.Assert(err == nil)
    }
}

func mocData() { // TODO: test only
    user1 := &User{1, []byte{'u', 's', 'e', 'r', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, crypto.Hash([]byte{'u', 's', 'e', 'r', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})}
    user2 := &User{2, []byte{'u', 's', 'e', 'r', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, crypto.Hash([]byte{'u', 's', 'e', 'r', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})}

    _ = AddUser(user1.Name, user1.Password)
    _ = AddUser(user2.Name, user2.Password)
}

func IsAdmin(user *User) bool { return user.Id == 0 } // as users are being verified & authenticated right after establishing a connection

func FindUser(username []byte, unhashedPassword []byte) *User { // nillable result
    utils.Assert(len(username) > 0 && len(unhashedPassword) > 0)

    this.rwMutex.RLock()
    result := this.users.FindOne(*(this.ctx), bson.D{{fieldName, username}})
    this.rwMutex.RUnlock()

    if result.Err() != nil { return nil }

    if user := new(User); result.Decode(user) == nil {
        if crypto.CompareWithHash(user.Password, unhashedPassword) { return user } else { return nil }
    } else {
        return nil
    }
}

func usernameAlreadyInUse(username []byte) bool { // username must be unique
    utils.Assert(len(username) > 0)
    result := this.users.FindOne(*(this.ctx), bson.D{{fieldName, username}})
    return result.Err() == nil
}

func availableUserId() *uint32 { return this.idsPool.TakeId() }

func AddUser(username []byte, hashedPassword []byte) *User { // nillable result
    utils.Assert(len(username) > 0 && len(hashedPassword) == int(crypto.HashSize))
    this.rwMutex.Lock()

    if usernameAlreadyInUse(username) {
        this.rwMutex.Unlock()
        return nil
    }

    userId := availableUserId()
    if userId == nil {
        this.rwMutex.Unlock()
        return nil
    }
    utils.Assert(*userId > 0)

    result, err := this.users.InsertOne(*(this.ctx), User{Id: *userId, Name: username, Password: hashedPassword})
    if result == nil || err != nil {
        this.rwMutex.Unlock()
        return nil
    }

    result2 := this.users.FindOne(*(this.ctx), bson.D{{fieldRealId, result.InsertedID}})
    utils.Assert(result2.Err() == nil)

    user := new(User)
    utils.Assert(result2.Decode(user) == nil)
    utils.Assert(user.Id > 0 && reflect.DeepEqual(username, user.Name) && reflect.DeepEqual(hashedPassword, user.Password))

    this.rwMutex.Unlock()
    return user
}

// TODO: DeleteUser(...)

func GetAllUsers() []User {
    this.rwMutex.RLock()
    cursor, err := this.users.Find(*(this.ctx), bson.D{})
    this.rwMutex.RUnlock()

    utils.Assert(err == nil)

    var users []User
    utils.Assert(cursor.All(*(this.ctx), &users) == nil && len(users) > 0)
    return users
}

func GetUsersCount() uint32 {
    this.rwMutex.RLock()
    count, err := this.users.EstimatedDocumentCount(*(this.ctx))
    this.rwMutex.RUnlock()

    utils.Assert(err == nil)
    return uint32(count)
}

func UserExists(id uint32) bool {
    this.rwMutex.RLock()
    result := this.users.FindOne(*(this.ctx), bson.D{{fieldId, id}})
    this.rwMutex.RUnlock()

    return result.Err() == nil
}

func GetMessagesFromOrForUser(from bool, id uint32, afterTimestamp uint64) []Message {
    var field string
    if from { field = fieldFrom } else { field = fieldTo }

    this.rwMutex.RLock()
    cursor, err := this.messages.Find(
        *(this.ctx),
        bson.M{field: id, fieldTimestamp: bson.M{"$gt": afterTimestamp}},
        options.Find().SetSort(bson.D{{fieldTimestamp, 1}}),
    )
    this.rwMutex.RUnlock()

    utils.Assert(err == nil)

    var messages []Message
    utils.Assert(cursor.All(*(this.ctx), &messages) == nil)
    return messages
}

func AddMessage(timestamp uint64, from uint32, to uint32, body []byte) bool {
    this.rwMutex.Lock()
    result, err := this.messages.InsertOne(*(this.ctx), Message{timestamp, from, to, body})
    this.rwMutex.Unlock()

    return result != nil && err == nil
}

func DeleteAllMessagesFromAllUsers() bool {
    this.rwMutex.Lock()
    result, err := this.messages.DeleteMany(*(this.ctx), bson.D{})
    this.rwMutex.Unlock()

    utils.Assert(err == nil)
    return result.DeletedCount > 0
}
