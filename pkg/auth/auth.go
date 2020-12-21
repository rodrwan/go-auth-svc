package auth

import (
	"context"
	"errors"
	"time"

	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/rodrwan/go-auth-svc"
)

// Service Auth service to handle jwt serialization.
type Service struct {
	AccessSecret  []byte
	RefreshSecret []byte

	Store *redis.Client
}

// GetAuthData extract data from token.
func (svc *Service) GetAuthData(ctx context.Context, token string) (*auth.Data, error) {
	claims := &auth.Claims{}
	data, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return svc.AccessSecret, nil
	})
	if err != nil {
		return nil, err
	}

	val, ok := data.Claims.(*auth.Claims)
	if !ok {
		return nil, errors.New("invalid token")
	}

	return val.Data, nil
}

// CreateAuthData Creates a new Auth.
func (svc *Service) CreateAuthData(ctx context.Context, referenceID string, payload []byte) (*auth.Auth, error) {
	tokens, err := auth.CreateTokensWithSecrets(referenceID, string(payload), svc.AccessSecret, svc.RefreshSecret)
	if err != nil {
		return nil, err
	}

	// insert new token into db
	if err := svc.CreateAuth(referenceID, tokens); err != nil {
		return nil, err
	}

	return &auth.Auth{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

// CreateAuth insert token into store
func (svc *Service) CreateAuth(referenceID string, ad *auth.Data) error {
	at := time.Unix(ad.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(ad.RtExpires, 0)
	now := time.Now()

	atCreated, err := svc.Store.Set(ad.AccessUUID, referenceID, at.Sub(now)).Result()
	if err != nil {
		return err
	}

	rtCreated, err := svc.Store.Set(ad.RefreshUUID, referenceID, rt.Sub(now)).Result()
	if err != nil {
		return err
	}

	if atCreated == "0" || rtCreated == "0" {
		return errors.New("no record inserted")
	}

	return nil
}

// RefreshAuthData Update and existing Auth.
func (svc *Service) RefreshAuthData(ctx context.Context, auth *auth.Auth) (*auth.Auth, error) {
	// TODO: get refresh token from context
	// verify refresh token
	// token is valid?
	// get refresh token uuid
	// delete refresh token by uuid
	// create new access_token and refresh token
	return nil, errors.New("not implemented")
}

// BlockAuthData Block an existing Auth, this is intended to prevent future hack or stolen token
// this will be store jwt metadata in a redis database.
func (svc *Service) BlockAuthData(ctx context.Context, auth *auth.Auth) error {
	// get access_token from context
	// remove tokens from store
	return nil
}
