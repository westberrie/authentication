package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var AccessKey = []byte("golang")
var RefreshKey = []byte("medods")

type Tokens struct {
	Guid    string `json: "guid"`
	Access  string `json: "accessToken"`
	Refresh string `json: "refreshToken"`
}

type Claims struct {
	Guid string `json: "guid"`
	jwt.StandardClaims
}

type RefreshClaims struct {
	Guid string `json: "guid"`
	Time int64  `json: "time"`
	jwt.StandardClaims
}

func CreateNewTokenPair(w *http.ResponseWriter, guid string) *Tokens {
	accessToken, err := CreateAccessToken(guid)
	if err != nil {
		(*w).WriteHeader(http.StatusNotImplemented)
		return nil
	}

	refreshToken, err := CreateRefreshToken(guid)
	if err != nil {
		(*w).WriteHeader(http.StatusNotImplemented)
		return nil
	}

	user, err := UpdateRefreshToken(refreshToken, guid)
	if err != nil {
		(*w).WriteHeader(http.StatusNotModified)
		return nil
	}

	return &Tokens{Guid: user.Guid, Access: accessToken, Refresh: refreshToken}
}

var t int64

func CreateAccessToken(guid string) (string, error) {
	expirationTimeAccess := time.Now().Add(time.Minute * 30).Unix()
	claims := &Claims{
		Guid: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTimeAccess,
		},
	}

	t = expirationTimeAccess

	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(AccessKey)
}

func CreateRefreshToken(guid string) (string, error) {
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["Guid"] = guid
	rtClaims["Time"] = t
	rtClaims["exp"] = time.Now().Add(time.Hour * 24 * 7).Unix()

	return refreshToken.SignedString(RefreshKey)
}

func ValidateAccessToken(w *http.ResponseWriter, token string) (string, int64) {
	claims := &Claims{}

	jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return AccessKey, nil
	})

	return claims.Guid, claims.ExpiresAt
}

func ValidateRefreshToken(w *http.ResponseWriter, token string) (string, int64) {
	filter := bson.D{primitive.E{Key: "refresh_token", Value: token}}
	answer := CheckData(filter)
	if !answer {
		(*w).Write([]byte(fmt.Sprintf("Refresh Token Is Invalid")))
		return "", 0
	}

	claims := &RefreshClaims{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return RefreshKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			(*w).WriteHeader(http.StatusUnauthorized)
			return "", 0
		}
		(*w).Write([]byte(fmt.Sprintf(err.Error())))
		return "", 0
	}

	if !tkn.Valid {
		(*w).WriteHeader(http.StatusUnauthorized)
		return "", 0
	}

	return claims.Guid, claims.Time
}
