package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func main() {
	ConnectionToMongo()

	mux := http.NewServeMux()
	mux.Handle("/get", http.HandlerFunc(GetTokens))
	mux.Handle("/refresh", http.HandlerFunc(RefreshToken))

	s := http.Server{
		Addr:    ":3000",
		Handler: mux,
	}
	s.ListenAndServe()
}

type Guid struct {
	Guid string `json: "guid"`
}

type TokenPair struct {
	AccessToken  string `json: "accessToken"`
	RefreshToken string `json: "refreshToken"`
}

func GetTokens(w http.ResponseWriter, r *http.Request) {
	var guid Guid

	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Host", "localhost")

	err := json.NewDecoder(r.Body).Decode(&guid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	filter := bson.D{primitive.E{Key: "_id", Value: guid.Guid}}
	answer := CheckData(filter)
	if !answer {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	tokesPair := CreateNewTokenPair(&w, guid.Guid)
	if tokesPair == nil {
		return
	}

	json.NewEncoder(w).Encode(tokesPair)
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var tokenPair TokenPair

	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Host", "localhost")

	err := json.NewDecoder(r.Body).Decode(&tokenPair)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessGuid, accessTime := ValidateAccessToken(&w, tokenPair.AccessToken)
	if accessGuid == "" {
		w.Write([]byte(fmt.Sprintf("Wrong Access Token")))
		return
	}

	refreshGuid, refreshTime := ValidateRefreshToken(&w, tokenPair.RefreshToken)
	if refreshGuid == "" {
		return
	}

	if accessGuid == refreshGuid && accessTime == refreshTime {
		tokesPair := CreateNewTokenPair(&w, refreshGuid)
		if tokesPair == nil {
			return
		}

		json.NewEncoder(w).Encode(tokesPair)
	} else {
		w.Write([]byte(fmt.Sprintf("Wrong Pair Of Tokens")))
	}
}
