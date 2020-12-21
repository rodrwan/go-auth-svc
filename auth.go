package auth

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
)

// Data represets a jwt token metadata
type Data struct {
	Data         string `json:"data,omitempty"`
	AccessToken  string `json:"-"`
	RefreshToken string `json:"-"`
	AccessUUID   string `json:"access_uuid,omitempty"`
	RefreshUUID  string `json:"refresh_uuid,omitempty"`
	AtExpires    int64  `json:"-"`
	RtExpires    int64  `json:"-"`
}

// Auth represents auth data.
type Auth struct {
	AccessToken  string `json:"-"`
	RefreshToken string `json:"-"`
}

// Claims join Data and StandardClaims from jwt.
type Claims struct {
	jwt.StandardClaims
	Data        *Data  `json:"data"`
	ReferenceID string `json:"reference_id"`
}

// Service define basic behavior to handle Authentication process.
type Service interface {
	// Get payload inside token
	GetAuthData(ctx context.Context, token string) (*Data, error)

	// Creates a new Auth.
	CreateAuthData(ctx context.Context, referenceID string, payload []byte) (*Auth, error)

	// Update and existing Auth.
	RefreshAuthData(ctx context.Context, auth *Auth) (*Auth, error)

	// Block an existing Auth, this is intended to prevent future hack or stolen token
	// this will be store jwt metadata in a redis database.
	BlockAuthData(ctx context.Context, auth *Auth) error
}

// CreateTokensWithSecrets creates a new access_token and refresh_token with the given auth data and secret.
func CreateTokensWithSecrets(referenceID, data string, aSecret, rSecret []byte) (*Data, error) {
	iat := time.Now()
	aExp := time.Now().Add(time.Minute * 15)
	rExp := time.Now().Add(time.Hour * 24 * 7)

	jwtData := &Data{
		AccessUUID:  uuid.NewV4().String(),
		RefreshUUID: uuid.NewV4().String(),
		AtExpires:   aExp.Unix(),
		RtExpires:   rExp.Unix(),
	}

	aStdClms := jwt.StandardClaims{
		Id:        uuid.NewV4().String(),
		IssuedAt:  iat.Unix(),
		ExpiresAt: aExp.Unix(),
	}
	atClaims := &Claims{
		StandardClaims: aStdClms,
		Data: &Data{
			AccessUUID: jwtData.AccessUUID,
			Data:       data,
		},
		ReferenceID: referenceID,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	accessToken, err := at.SignedString(aSecret)
	if err != nil {
		return nil, err
	}

	jwtData.AccessToken = accessToken

	rStdClms := jwt.StandardClaims{
		Id:        uuid.NewV4().String(),
		IssuedAt:  iat.Unix(),
		ExpiresAt: rExp.Unix(),
	}
	rtClaims := &Claims{
		StandardClaims: rStdClms,
		Data: &Data{
			RefreshUUID: jwtData.RefreshUUID,
		},
		ReferenceID: referenceID,
	}

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	refreshToken, err := rt.SignedString(rSecret)
	if err != nil {
		return nil, err
	}

	jwtData.RefreshToken = refreshToken

	return jwtData, nil
}
