package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	// "github.com/golang-jwt/jwt"
	// "github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashPass), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	strToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return strToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString, claims,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(tokenSecret), nil
		})
	if err != nil {
		return uuid.UUID{}, err
	}
	if !token.Valid {
		return uuid.UUID{}, jwt.ErrSignatureInvalid
	}
	userId, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}
	return userId, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	token := headers.Get("Authorization")
	if token == "" {
		return token, fmt.Errorf("no authorization token")
	}
	if !strings.HasPrefix(token, "Bearer ") {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}
	authToken := strings.TrimPrefix(token, "Bearer")
	authToken = strings.TrimSpace(authToken)
	if token == "" {
		return "", fmt.Errorf("token is empty after Bearer prefix")
	}
	return authToken, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	key := headers.Get("Authorization")
	if key == "" {
		return "", fmt.Errorf("did not authorization key")
	}
	if !strings.HasPrefix(key, "ApiKey ") {
		return "", fmt.Errorf("key format is not valid, has not prefix ApiKey")
	}
	apiKey := strings.TrimPrefix(key, "ApiKey")
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return "", fmt.Errorf("has not apikey")
	}
	return apiKey, nil
}
