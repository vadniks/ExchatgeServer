
package database

import (
    "ExchatgeServer/utils"
    "context"
    "fmt"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

const mongoUrl = "mongodb://mongodb:27017/exchatge"
const databaseName = "db"
const collectionUsers = "users"
const collectionConversations = "conversations"
const collectionMessages = "messages"

type User struct { // TODO: store each conversation's encryption key on client's side for each client, store name of each participant of each conversation on the client side
    id uint
}

func Init() {
    ctx := context.TODO()

    client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUrl))
    utils.Assert(err == nil)

    defer func() { utils.Assert(client.Disconnect(ctx) == nil) }()

    collection := client.Database(databaseName).Collection(collectionUsers)

    fmt.Println("a")
    cursor, err := collection.Find(ctx, bson.D{}) // TODO: test only
    if err != nil { fmt.Println(err) }
    utils.Assert(err == nil)
    fmt.Println("b")
    values, err := cursor.Current.Values()
    utils.Assert(err == nil)
    size := len(values)
    fmt.Println(size)
    if size > 0 { return }

    result, err := collection.InsertOne(ctx, User{0})
    utils.Assert(err == nil)
    fmt.Println(result.InsertedID)
}
