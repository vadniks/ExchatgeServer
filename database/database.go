
package database

import (
    "ExchatgeServer/utils"
    "context"
    "fmt"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

const mongoUrl = "mongodb://127.0.0.1:27017/exchatge"
const databaseName = "db"
const collectionUsers = "users"
const collectionConversations = "conversations"
const collectionMessages = "messages"

type User struct { // TODO: store each conversation's encryption key on client's side for each client, store name of each participant of each conversation on the client side
    id uint32
}

func Init() {
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    defer func() { utils.Assert(client.Disconnect(ctx) == nil) }()

    collection := client.Database(databaseName).Collection(collectionUsers)

    fmt.Println("a")
    count, err := collection.CountDocuments(ctx, User{}) // TODO: test only
    utils.Assert(err == nil)
    fmt.Println(count)

    result := collection.FindOne(ctx, User{10})
    fmt.Println(result.Err())
    var user User
    err = result.Decode(&user)
    fmt.Println(err)
    fmt.Println(user.id)

    //result, err := collection.InsertOne(ctx, User{5})
    //utils.Assert(err == nil)
    //fmt.Println(result.InsertedID)
}
