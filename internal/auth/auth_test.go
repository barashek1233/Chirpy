package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

const testSecret = "my-super-secret-key-for-testing"

func TestMakeAndAvalidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenString, err := MakeJWT(userID, testSecret, 1*time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT вернул ошибку: %v", err)
	}

	if tokenString == "" {
		t.Fatal("MakeJWT вернул пустой токен")
	}

	parserdUserID, err := ValidateJWT(tokenString, testSecret)
	if err != nil {
		t.Fatalf("ValidateJWT вернул ошибку: %v", err)
	}
	if parserdUserID != userID {
		t.Errorf("ожидался %s, получен %s", userID, parserdUserID)
	}
}

func TestValidateExpiredJWT(t *testing.T) {
	userID := uuid.New()

	// Создаём токен, который истекает 1 час назад
	tokenString, err := MakeJWT(userID, testSecret, -1*time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT вернул ошибку: %v", err)
	}

	// Пытаемся валидировать
	_, err = ValidateJWT(tokenString, testSecret)
	if err == nil {
		t.Fatal("ожидалась ошибка из-за истечения срока, но её нет")
	}
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	userID := uuid.New()

	tokenString, err := MakeJWT(userID, testSecret, 1*time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT вернул ошибку: %v", err)
	}

	// Используем другой секрет
	_, err = ValidateJWT(tokenString, "wrong-secret")
	if err == nil {
		t.Fatal("ожидалась ошибка из-за неверного секрета, но её нет")
	}
}

func TestValidateEmptyJWT(t *testing.T) {
	_, err := ValidateJWT("", testSecret)
	if err == nil {
		t.Fatal("ожидалась ошибка для пустого токена")
	}
}
