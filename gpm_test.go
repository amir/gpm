package gpm

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLogin(t *testing.T) {
	authToken := time.Now().Unix()
	googleLoginAuth := fmt.Sprintf("GoogleLogin auth=%d", authToken)
	gcl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("accountType") == "HOSTED_OR_GOOGLE" &&
			r.FormValue("Email") == "test@example.com" && r.FormValue("Passwd") == "test" {
			fmt.Fprintf(w, "Auth=%d", authToken)
		}
	}))
	gpme := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != googleLoginAuth {
			w.WriteHeader(http.StatusForbidden)
			t.Errorf("Expected: %s, Got: %s", googleLoginAuth, r.Header.Get("Authorization"))
		}
	}))

	defer gpme.Close()
	defer gcl.Close()

	googleClientLogin = gcl.URL
	googlePlayMusicEndpoint = gpme.URL

	c := New("test@example.com", "test")
	err := c.Login()

	if err != nil {
		t.Error(err)
	}
}
