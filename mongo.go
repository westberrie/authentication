package main

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Guid          string `bson:"_id"`
	Refresh_token string `bson:"refresh_token"`
}

var collection *mongo.Collection
var ctx = context.TODO()

func ConnectionToMongo() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017/")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	collection = client.Database("auth").Collection("users")
}

func CheckData(filter bson.D) bool {
	var user User

	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false
		}
		log.Fatal(err)
	}

	return true
}

func UpdateRefreshToken(token string, guid string) (*User, error) {
	var user User
	filter := bson.D{primitive.E{Key: "_id", Value: guid}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: "refresh_token", Value: token},
	}}}

	result := collection.FindOneAndUpdate(ctx, filter, update)
	if result.Err() != nil {
		return nil, result.Err()
	}

	decodeErr := result.Decode(&user)

	return &user, decodeErr
}
