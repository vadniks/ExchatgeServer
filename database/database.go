
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

var adminUsername = []byte{'a', 'd', 'm', 'i', 'n'}
var adminPassword = crypto.Hash([]byte{'a', 'd', 'm', 'i', 'n'})

const fieldId = "Id"
const fieldName = "Name"
const fieldPassword = "Password"

type User struct {
    Id uint32 `bson:"id"`
    Name []byte `bson:"name"`
    Password []byte `bson:"password"`
}

// TODO: store each conversation's encryption key on client's side for each client, store Name of each participant of each conversation on the client side

type database struct {
    ctx *context.Context
    collection *mongo.Collection
}
var this *database = nil

func Init() {
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    defer func() { utils.Assert(client.Disconnect(ctx) == nil) }()

    collection := client.Database(databaseName).Collection(collectionUsers)
    this = &database{&ctx, collection}

    addAdminIfNotExists()
}

func addAdminIfNotExists() {
    usr := User{Id: 0, Name: adminUsername, Password: adminPassword}
    if result := this.collection.FindOne(*(this.ctx), usr); result.Err() == mongo.ErrNoDocuments {
        _, err := this.collection.InsertOne(*(this.ctx), usr)
        utils.Assert(err == nil)
    }
}

func IsAdmin(usr *User) bool {
    if result := this.collection.FindOne(*(this.ctx), bson.D{{fieldId, 0}}); result.Err() == nil {
        var temp User
        utils.Assert(result.Decode(&temp) == nil)
        return reflect.DeepEqual(temp.Name, usr.Name) && reflect.DeepEqual(temp.Password, usr.Password)
    } else {
        return false
    }
}

func CheckUser(usr *User) bool {
    return this.collection.FindOne(*(this.ctx), bson.D{
        {fieldName, usr.Name},
        {fieldPassword, usr.Password},
    }).Err() == nil
}

func AddUser(usr *User) bool {
    result, err := this.collection.InsertOne(*(this.ctx), *usr)
    return result != nil && err == nil
}
