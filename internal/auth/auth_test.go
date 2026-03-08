package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		t.Errorf("Failed test -> %s\n", err)
		return
	}

	token, err := MakeJWT(uuid, "Test-Secret", time.Duration(5*time.Minute))
	if err != nil {
		t.Errorf("Failed test MakeJWT() -> %s\n", err)
		return
	}

	if len(token) <= 0 {
		t.Errorf("Failed test MakeJWT() -> Token generated is invalid.\n")
		return
	}

	fmt.Printf("-- Test MakeJWT() Result -> %s\n", token)
}

func TestValidateJWT(t *testing.T) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		t.Errorf("Failed test -> %s\n", err)
		return
	}

	token, err := MakeJWT(uuid, "Test-Secret", time.Duration(5*time.Minute))
	if err != nil {
		t.Errorf("Failed test MakeJWT() -> %s\n", err)
		return
	}

	uid, err := ValidateJWT(token, "Test-Secret")
	if err != nil {
		t.Errorf("Failed test ValidateJWT() -> %s\n", err)
		return
	}

	fmt.Printf("-- Test ValidateJWT() Result -> \n-- IN UUID: %s\n-- OUT UUID: %s\n-- Token: %s", uuid, uid.String(), token)
}

func TestGetBearerToken(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjaGlycHktYWNjZXNzIiwic3ViIjoiYjEyMzQzNjAtYzhiYi00YzljLThmNWQtMmQzNzNjZTA5MmE3IiwiZXhwIjoxNzcxNDQ5MzEzLCJpYXQiOjE3NzE0NDc1MTN9.3xpdUqNDfxJUzwWDthcPhySX5rTQ2stpqEfQ2pn2zF4")

	token, err := GetBearerToken(header)
	if err != nil {
		t.Errorf("Failed test GetBearerToken() -> %s | %s\n", token, err)
		return
	}

	fmt.Printf("-- Test GetBearerToken() Result -> \n-- OUT TOKEN: %s\n", token)
}
