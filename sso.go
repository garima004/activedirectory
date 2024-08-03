package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	// "os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "6c17737e-3175-4d30-8224-68cbfe4d8407"
	clientSecret = "s1E8Q~wHnI5R3lrp5hS6ue8wVxcJ8LYxzs7eWcou"
	redirectURL  = "http://localhost:8080/callback"
	tenantID     = "03bc542b-c613-436a-a090-916ce925cee0"
	adfsURL      = "https://login.microsoftonline.com/" + tenantID + "/v2.0"
)

var oauth2Config *oauth2.Config
var verifier *oidc.IDTokenVerifier

func init() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, adfsURL)
	if err != nil {
		log.Fatal(err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Println("Server is running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<html><body><a href="/login">Login with ADFS</a></body></html>`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := "random" // You can generate a random state string for security
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	log.Printf("Authorization code: %s", code) // Debugging: Print the authorization code
	if code == "" {
		http.Error(w, "Code not found in the query string", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "User authenticated: %s", claims.Email)
}
