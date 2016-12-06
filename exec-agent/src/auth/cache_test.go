package auth

import (
	"testing"
	"time"
)

func TestTokenCache(t *testing.T) {
	cache := &TokenCache{
		tokens : make(map[string]time.Time),
		expireTimeout: 0,
	}

	token := "my-token"

	cache.Put(token)
	if !cache.Contains(token) {
		t.Fatalf("Cache must contain token %s", token)
	}

	cache.Expire(token)
	if cache.Contains(token) {
		t.Fatalf("Cache must not contain token %s", token)
	}
}

func TestExpiresTokensCreatedBeforeGivenPointOfTime(t *testing.T) {
	cache := &TokenCache{
		tokens : make(map[string]time.Time),
		expireTimeout: 0,
	}

	cache.Put("token1")
	afterToken1Put := time.Now()
	cache.Put("token2")

	cache.expireAllBefore(afterToken1Put)

	if cache.Contains("token1") {
		t.Fatal("Cache must not contain token1")
	}
	if !cache.Contains("token2") {
		t.Fatal("Cache must contain token2")
	}
}