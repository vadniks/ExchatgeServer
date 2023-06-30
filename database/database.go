
package database

import (
    "ExchatgeServer/crypto"
    "ExchatgeServer/utils"
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "reflect"
)

const mongoUrl = "mongodb://127.0.0.1:27017/exchatge"
const databaseName = "db"
const collectionUsers = "users"
const collectionConversations = "conversations"
const collectionMessages = "messages"

const fieldRealId = "_id"
const fieldId = "id"
const fieldName = "name"
const fieldPassword = "password"

type User struct {
    Id uint32 `bson:"id"`
    Name []byte `bson:"name"`
    Password []byte `bson:"password"` // salty-hashed
}

var adminUsername = []byte{'a', 'd', 'm', 'i', 'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var adminPassword = crypto.Hash([]byte{'a', 'd', 'm', 'i', 'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

func (user *User) passwordHashed() *User {
    user.Password = crypto.Hash(user.Password)
    return user
}

// TODO: store each conversation's encryption key on client's side for each client, store Name of each participant of each conversation on the client side

type database struct {
    ctx *context.Context
    collection *mongo.Collection
    client *mongo.Client
}
var this *database = nil

func Init() { // TODO: authenticate database connection with password
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    collection := client.Database(databaseName).Collection(collectionUsers)
    this = &database{&ctx, collection, client}

    addAdminIfNotExists()
    mocData() // TODO: test only
}

func Destroy() { utils.Assert(this.client.Disconnect(*(this.ctx)) == nil) }

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
    user1 := &User{1, []byte{'u', 's', 'e', 'r', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, crypto.Hash([]byte{'u', 's', 'e', 'r', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})}
    user2 := &User{2, []byte{'u', 's', 'e', 'r', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, crypto.Hash([]byte{'u', 's', 'e', 'r', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})}

    _ = AddUser(user1.Name, user1.Password)
    _ = AddUser(user2.Name, user2.Password)
}

func IsAdmin(user *User) bool { return user.Id == 0 } // as users are being verified & authenticated right after establishing a connection

func FindUser(username []byte, unhashedPassword []byte) *User { // nillable result
    utils.Assert(len(username) > 0 && len(unhashedPassword) > 0)

    result := this.collection.FindOne(*(this.ctx), bson.D{{fieldName, username}})
    if result.Err() != nil { return nil }

    if user := new(User); result.Decode(user) == nil {
        if crypto.CompareWithHash(user.Password, unhashedPassword) { return user } else { return nil }
    } else {
        return nil
    }
}

func usernameAlreadyInUse(username []byte) bool { // username must be unique
    utils.Assert(len(username) > 0)
    result := this.collection.FindOne(*(this.ctx), bson.D{{fieldName, username}})
    return result.Err() == nil
}

func availableUserId() uint32 { // TODO: maybe just use the real mongodb's _id?
    var biggestId uint32 = 0
    for _, i := range GetAllUsers() { if id := i.Id; id > biggestId { biggestId = id } }
    return biggestId + 1
}

func AddUser(username []byte, hashedPassword []byte) *User { // nillable result
    utils.Assert(len(username) > 0 && len(hashedPassword) == int(crypto.HashSize))
    if usernameAlreadyInUse(username) { return nil }

    userId := availableUserId()
    utils.Assert(userId > 0)

    result, err := this.collection.InsertOne(*(this.ctx), User{Id: userId, Name: username, Password: hashedPassword})
    if result == nil || err != nil { return nil }

    result2 := this.collection.FindOne(*(this.ctx), bson.D{{fieldRealId, result.InsertedID}})
    utils.Assert(result2.Err() == nil)

    user := new(User)
    utils.Assert(result2.Decode(user) == nil)
    utils.Assert(user.Id > 0 && reflect.DeepEqual(username, user.Name) && reflect.DeepEqual(hashedPassword, user.Password))
    return user
}

func GetAllUsers() []User {
    cursor, err := this.collection.Find(*(this.ctx), bson.D{})
    utils.Assert(err == nil)

    var users []User
    utils.Assert(cursor.All(*(this.ctx), &users) == nil && len(users) > 0)
    return users
}
