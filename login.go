package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var (
	clientID     = "6c17737e-3175-4d30-8224-68cbfe4d8407"
	clientSecret = "s1E8Q~wHnI5R3lrp5hS6ue8wVxcJ8LYxzs7eWcou"
	redirectURL  = "http://localhost:8080/callback"
	store        = sessions.NewCookieStore([]byte("super-secret-key"))

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     microsoft.AzureADEndpoint("03bc542b-c613-436a-a090-916ce925cee0"),
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}
)

func init() {
	gob.Register(&oauth2.Token{})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "session-name")
	session.Values["token"] = token
	session.Values["authenticated"] = true
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/welcome", http.StatusFound)
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	token, ok := session.Values["token"].(*oauth2.Token)
	if !ok || !token.Valid() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	client := oauth2Config.Client(context.Background(), token)
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	userInfo := struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"mail"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Welcome, %s (%s)!", userInfo.DisplayName, userInfo.Email)
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/welcome", welcomeHandler)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
