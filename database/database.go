
package database

import (
    "ExchatgeServer/utils"
    "context"
    "fmt"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

const mongoUrl = "mongodb://127.0.0.1:27017/exchatge"
const databaseName = "db"
const collectionUsers = "users"
const collectionConversations = "conversations"
const collectionMessages = "messages"

// TODO: store each conversation's encryption key on client's side for each client, store name of each participant of each conversation on the client side

func Init() {
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    defer func() { utils.Assert(client.Disconnect(ctx) == nil) }()

    collection := client.Database(databaseName).Collection(collectionUsers)

    // TODO: test only
    result := collection.FindOne(ctx, bson.D{{"id", 1}})
    fmt.Println(result.Err())
    var user bson.D
    err = result.Decode(&user)
    fmt.Println(err)
    fmt.Println(user)

    result2, err := collection.InsertOne(ctx, bson.D{{"id", 1}})
    utils.Assert(err == nil)
    fmt.Println(result2.InsertedID)
}
