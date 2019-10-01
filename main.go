package main

import (
	"flag"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"log"
	"math/rand"
	"net/http"
	"sort"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	l := len(letterBytes)
	for i := range b {
		b[i] = letterBytes[rand.Intn(l)]
	}
	return string(b)
}

func main() {
	endpointPtr := flag.String("endpoint", "", "OpenID Connect Endpoint")
	clientIDPtr := flag.String("client-id", "", "Client ID")
	clientSecretPtr := flag.String("client-secret", "", "Client secret")
	callbackPtr := flag.String("callback", "", "Callback url prefix")
	addrPtr := flag.String("listen", "0.0.0.0:7777", "Address + port to listen on")
	groupPtr := flag.String("group", "", "Group user is required to be in. [Optional]")
	cookieDomainPtr := flag.String("cookie-domain", "", "Cookie domain")

	flag.Parse()

	if (*endpointPtr == "") || (*clientIDPtr == "") || (*clientSecretPtr == "") || (*callbackPtr == "") || (*addrPtr == "") || (*cookieDomainPtr == "") {
		log.Fatal("Missing flag.")
	}

	state := RandStringBytes(16)
	store := sessions.NewCookieStore([]byte(RandStringBytes(16)))
	sessionName := RandStringBytes(16)

	store.Options.Domain = *cookieDomainPtr

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, *endpointPtr)
	if err != nil {
		log.Fatal(err)
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: *clientIDPtr})

	config := oauth2.Config{
		ClientID:     *clientIDPtr,
		ClientSecret: *clientSecretPtr,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("%s/callback", *callbackPtr),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, sessionName)

		//Store header values in case we need them.
		session.Values["forwarded-uri"] = r.Header.Get("X-Forwarded-Uri")
		session.Values["forwarded-host"] = r.Header.Get("X-Forwarded-Host")
		session.Values["forwarded-proto"] = r.Header.Get("X-Forwarded-Proto")
		keys, ok := r.URL.Query()["group"]
		if !ok || len(keys[0]) < 1 {
			session.Values["group"] = *groupPtr
		} else {
			session.Values["group"] = string(keys[0])
		}
		session.Save(r, w)

		//Parse and verify ID Token payload.
		val := session.Values["token"]

		if val == nil {
			//No token, redirect.
			http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
			return
		}

		token, ok := val.(string)
		if !ok {
			//Handle the case that it's not an expected type
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		//Verify token
		idToken, err := idTokenVerifier.Verify(ctx, string(token))

		if err != nil {
			//Invalid token, redirect to login
			http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
			return
		}

		var claims struct {
			Groups []string `json:"groups"`
		}

		if err := idToken.Claims(&claims); err != nil {
			//Claims error
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		val = session.Values["group"]

		if val != nil {
			group, ok := val.(string)
			if ok && group != "" {
				//Check if required group exists
				sort.Strings(claims.Groups)

				i := sort.SearchStrings(claims.Groups, group)

				if (i >= len(claims.Groups)) || (claims.Groups[i] != group) {
					http.Error(w, http.StatusText(http.StatusUnauthorized),
						http.StatusUnauthorized)
					return
				}
			}
		}

		fmt.Fprintf(w, "Ok")
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if state != r.URL.Query().Get("state") {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			// handle error
			http.Error(w, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}

		session, err := store.Get(r, sessionName)
		session.Values["token"] = rawIDToken
		session.Save(r, w)

		var claims struct {
			Groups []string `json:"groups"`
		}

		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		val := session.Values["group"]

		if val != nil {
			group, ok := val.(string)
			if ok && group != "" {
				//Check if required group exists
				sort.Strings(claims.Groups)

				i := sort.SearchStrings(claims.Groups, group)

				if (i >= len(claims.Groups)) || (claims.Groups[i] != group) {
					http.Error(w, http.StatusText(http.StatusUnauthorized),
						http.StatusUnauthorized)
					return
				}
			}
		}

		val = session.Values["forwarded-uri"]

		if val == nil {
			//No forwarded uri, just say Ok.
			fmt.Fprintf(w, "Ok")
			return
		}

		uri, ok := val.(string)

		if !ok {
			// Handle the case that it's not an expected type
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		val = session.Values["forwarded-host"]

		if val == nil {
			//No forwarded uri, just say Ok.
			fmt.Fprintf(w, "Ok")
			return
		}

		host, ok := val.(string)

		if !ok {
			// Handle the case that it's not an expected type
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		val = session.Values["forwarded-proto"]

		if val == nil {
			//No forwarded uri, just say Ok.
			fmt.Fprintf(w, "Ok")
			return
		}

		proto, ok := val.(string)

		if !ok {
			// Handle the case that it's not an expected type
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%s://%s%s", proto, host, uri), http.StatusFound)
	})

	log.Printf("Listening on %s", *addrPtr)
	log.Fatal(http.ListenAndServe(*addrPtr, nil))
}
