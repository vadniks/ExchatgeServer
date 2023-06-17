
package database

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/utils"
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "reflect"
    "sync"
)

const mongoUrl = "mongodb://127.0.0.1:27017/exchatge"
const databaseName = "db"
const collectionUsers = "users"
const collectionConversations = "conversations"
const collectionMessages = "messages"

var adminUsername = []byte("admin")
var adminPassword = crypto.Hash([]byte("admin"))

const fieldId = "id"
const fieldName = "name"
const fieldPassword = "password"

type User struct {
    Id uint32 `bson:"id"`
    Name []byte `bson:"name"`
    Password []byte `bson:"password"`
}

func (user *User) passwordHashed() *User {
    user.Password = crypto.Hash(user.Password)
    return user
}

// TODO: store each conversation's encryption key on client's side for each client, store Name of each participant of each conversation on the client side

type database struct {
    ctx *context.Context
    collection *mongo.Collection
}
var this *database = nil

func Init(waitGroup *sync.WaitGroup) { // TODO: authenticate database connection with password
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    defer func() {
        utils.Assert(client.Disconnect(ctx) == nil)
        waitGroup.Done()
    }()

    collection := client.Database(databaseName).Collection(collectionUsers)
    this = &database{&ctx, collection}

    addAdminIfNotExists()
    mocData() // TODO: test only
}

func addAdminIfNotExists() { // admin is the only user that has id equal to 0 TODO: how about adding an isAdmin field?
    if result := this.collection.FindOne(
        *(this.ctx),
        bson.D{{fieldId, 0}, {fieldName, adminUsername}},
    ); result.Err() == mongo.ErrNoDocuments {
        _, err := this.collection.InsertOne(*(this.ctx), User{Id: 0, Name: adminUsername, Password: adminPassword})
        utils.Assert(err == nil)
    }
}

func mocData() { // TODO: test only
    user1 := &User{1, []byte("user1"), []byte("user1")}
    user2 := &User{2, []byte("user2"), []byte("user2")}

    if FindUser(user1.Name, user1.Password) == nil { AddUser(user1.passwordHashed()) }
    if FindUser(user2.Name, user2.Password) == nil { AddUser(user2.passwordHashed()) }
}

func IsAdmin(user *User) bool {
    utils.Assert(user != nil)

    if result := this.collection.FindOne(*(this.ctx), bson.D{{fieldId, 0}}); result.Err() == nil {
        var temp User
        utils.Assert(result.Decode(&temp) == nil)

        result := reflect.DeepEqual(temp.Name, user.Name) && reflect.DeepEqual(temp.Password, user.Password)
        if result { utils.Assert(user.Id == 0) } // TODO: rethink logic as what we have here is suspicious
        return result
    } else {
        utils.Assert(user.Id != 0)
        return false
    }
}

func FindUser(username []byte, unhashedPassword []byte) *User { // nillable result
    utils.Assert(len(username) > 0 && len(unhashedPassword) > 0)

    result := this.collection.FindOne(*(this.ctx), bson.D{{fieldName, username}})
    if result.Err() != nil { return nil }

    if user := new(User); result.Decode(user) == nil {
        crypto.CompareWithHash(user.Password, unhashedPassword)
        return user
    } else {
        return nil
    }
}

func AddUser(user *User) bool {
    utils.Assert(user != nil)
    result, err := this.collection.InsertOne(*(this.ctx), *user)
    return result != nil && err == nil
}
