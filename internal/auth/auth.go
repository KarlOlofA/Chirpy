package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthClaim struct {
	Id string `json:"id"`
	jwt.RegisteredClaims
}

func HashPassword(password string) (string, error) {

	params := argon2id.DefaultParams

	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func CompareHash(password string, hash string) (bool, error) {

	success, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}

	if !success {
		return false, nil
	}

	return true, nil
}

func MakeJWT(userId uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	t := time.Now().UTC()
	claims := AuthClaim{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "chirpy-access",
			IssuedAt:  jwt.NewNumericDate(t),
			ExpiresAt: jwt.NewNumericDate(t.Add(time.Duration(time.Minute * 30))),
			Subject:   userId.String(),
		},
		Id: userId.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaim{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return uuid.UUID{}, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*AuthClaim)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid claims")
	}

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID in claims: %w", err)
	}

	return uid, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")

	if len(authHeader) <= 0 {
		return "", errors.New("Bearer token too short")
	}

	prefix := authHeader[:len("bearer ")]

	if strings.ToLower(prefix) != "bearer " {
		return strings.ToLower(prefix), errors.New("Invalid bearer token")
	}

	token := strings.Split(authHeader, "Bearer ")[1]

	return token, nil
}

func MakeRefreshToken() (string, error) {

	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
