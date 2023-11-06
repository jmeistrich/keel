package runtime

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dchest/uniuri"
	"github.com/iancoleman/strcase"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/teamkeel/keel/events"
	"github.com/teamkeel/keel/functions"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/runtime/actions"
	"github.com/teamkeel/keel/runtime/apis/graphql"
	"github.com/teamkeel/keel/runtime/apis/httpjson"
	"github.com/teamkeel/keel/runtime/apis/jsonrpc"
	"github.com/teamkeel/keel/runtime/common"
	"github.com/teamkeel/keel/runtime/runtimectx"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var tracer = otel.Tracer("github.com/teamkeel/keel/runtime")
var Version string

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(logLevel())
}

func GetVersion() string {
	return Version
}

var (
	// Check the api documentation of `compose.Config` for further configuration options.
	config = &fosite.Config{
		AccessTokenLifespan:  time.Minute * 30,
		GlobalSecret:         secret,
		RefreshTokenLifespan: time.Hour * 24,
		// ...
	}

	// This is the example storage that contains:
	// * an OAuth2 Client with id "my-client" and secrets "foobar" and "foobaz" capable of all oauth2 and open id connect grant and response types.
	// * a User for the resource owner password credentials grant type with username "peter" and password "secret".
	//
	// You will most likely replace this with your own logic once you set up a real world application.
	store = storage.NewMemoryStore()

	// This secret is used to sign authorize codes, access and refresh tokens.
	// It has to be 32-bytes long for HMAC signing. This requirement can be configured via `compose.Config` above.
	// In order to generate secure keys, the best thing to do is use crypto/rand:
	//
	// ```
	// package main
	//
	// import (
	//	"crypto/rand"
	//	"encoding/hex"
	//	"fmt"
	// )
	//
	// func main() {
	//	var secret = make([]byte, 32)
	//	_, err := rand.Read(secret)
	//	if err != nil {
	//		panic(err)
	//	}
	// }
	// ```
	//
	// If you require this to key to be stable, for example, when running multiple fosite servers, you can generate the
	// 32byte random key as above and push it out to a base64 encoded string.
	// This can then be injected and decoded as the `var secret []byte` on server start.
	secret = []byte("some-cool-secret-that-is-32bytes")

	// privateKey is used to sign JWT tokens. The default strategy uses RS256 (RSA Signature with SHA-256)
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//	session = new(fosite.DefaultSession)
func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     user,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}

// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
var oauth2server = compose.ComposeAllEnabled(config, store, privateKey)

// var strategy = NewOAuth2HMACStrategy(config)

// var oauth2server = Compose(
// 	config,
// 	store,
// 	strategy,
// 	NewOAuth2AuthorizeExplicitHandler,
// 	OAuth2ClientCredentialsGrantFactory)

// MakeOAuthProvider produces a ready-to-use oauth configuration from one of Keel's
// approved OpenIDConnect and OAuth2 issuers.
func MakeOAuthProvider(issuer Issuer, clientConfig *OAuthClientConfiguration) (*oauth2.Config, bool, error) {
	switch _, isOidc := oidcIssuers[issuer]; {
	case isOidc:
		config, err := MakeOidcProvider(issuer, clientConfig)
		if err != nil {
			return nil, true, err
		}

		return config, true, nil
	case issuer == GitHub:
		config := &oauth2.Config{
			ClientID:     clientConfig.clientId,
			ClientSecret: clientConfig.clientSecret,
			RedirectURL:  "http://localhost:8000/auth/callback?provider=" + string(GitHub),
		}

		config.Endpoint = github.Endpoint
		config.Scopes = []string{"read:user", "user:email"}

		return config, isOidc, nil
	default:
		return nil, false, fmt.Errorf("unsupported oauth provider '%s'", string(issuer))
	}
}

// MakeOidcProvider produces a ready-to-use oauth configuration from a custom
// OpenIDConnect issuer
func MakeOidcProvider(issuer Issuer, clientConfig *OAuthClientConfiguration) (*oauth2.Config, error) {
	config := &oauth2.Config{
		ClientID:     clientConfig.clientId,
		ClientSecret: clientConfig.clientSecret,
		RedirectURL:  "http://localhost:8000/auth/callback?provider=" + string(issuer),
	}

	i := oidcIssuers[issuer]

	c, err := oidc.NewProvider(context.Background(), i.issuer)
	if err != nil {
		return nil, err
	}
	config.Endpoint = c.Endpoint()
	config.Scopes = []string{"openid", "email", "profile"}

	return config, nil
}

// oauth client configs by customer (from env)
var configuredProviders = map[Issuer]*OAuthClientConfiguration{
	Google: {
		clientId:     "247884616520-ft5a4aerlpth1p10sao3rb7f92padugf.apps.googleusercontent.com",
		clientSecret: "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",
	},
	Auth0: {
		clientId:     "7IBpqyPGxOd7QiWdfM1RGS801FWLb0oS",
		clientSecret: "0kwizo1rjb78Du3FmuabBrA63OMWiu9_o1rXKRibntePGBRp-oEWEB8WS4_to2ST",
	},
	GitHub: {
		clientId:     "da6bf0c8cda4f6b4056a",
		clientSecret: "6efcd8d3d3e5bf823e01114f4928229657ed1664",
	},
}

func NewHttpHandler(currSchema *proto.Schema) http.Handler {
	var handler common.ApiHandlerFunc
	if currSchema != nil {
		handler = NewHandler(currSchema)
	}

	httpHandler := func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "Runtime")
		defer span.End()

		span.SetAttributes(
			attribute.String("runtime_version", Version),
		)

		w.Header().Add("Content-Type", "application/json")

		if r.URL.Path == "/auth/providers" {
			indexHandler(w, r)
			return
		} else if r.URL.Path == "/auth/login" {
			// provides login paths for oauth issuers
			loginHandler(w, r)
			return
		} else if r.URL.Path == "/auth/callback" {
			// callback for oauth flow
			callbackHandler(ctx, w, r, currSchema)
			return
		} else if r.URL.Path == "/auth/token" {
			// provides tokens for refresh and token-exchange grants
			tokenHandler(ctx, w, r, currSchema)
			return
		}

		if handler == nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Cannot serve requests when schema contains errors"))
			return
		}

		ctx = runtimectx.WithIssuersFromEnv(ctx)

		// Collect request headers and add to runtime context
		// These are exposed in custom functions and in expressions
		headers := map[string][]string{}
		for k := range r.Header {
			headers[k] = r.Header.Values(k)
		}
		ctx = runtimectx.WithRequestHeaders(ctx, headers)
		r = r.WithContext(ctx)

		response := handler(r)

		// Add any custom headers to response, and join
		// into a single string where multi values exists
		for k, values := range response.Headers {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}

		span.SetAttributes(
			attribute.Int("response.status", response.Status),
		)

		w.WriteHeader(response.Status)
		_, _ = w.Write(response.Body)
	}

	return http.HandlerFunc(httpHandler)
}

// OIDC providers supported by Keel
type OidcProvider struct {
	//name   string
	// OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string /.well-known/openid-configuration to the Issuer. The syntax and semantics of .well-known are defined in RFC 5785 [RFC5785] and apply to the Issuer value when it contains no path component. openid-configuration MUST point to a JSON document compliant with this specification and MUST be returned using the application/json content type.
	issuer string
	//scopes []string
}

// Issuer identifiers
type Issuer string

const (
	Google   Issuer = "google"
	Auth0    Issuer = "auth0"
	GitHub   Issuer = "github"
	Facebook Issuer = "facebook"
)

// OIDC issuer configuration
var oidcIssuers = map[Issuer]*OidcProvider{
	Google: {
		issuer: "https://accounts.google.com",
	},
	Auth0: {
		issuer: "https://dev-sa8zx4qtm8w0yxek.us.auth0.com/",
	},
	Facebook: {
		issuer: "https://facebook.com",
	},
	"CustomOIDC": {
		issuer: "https://mycustomoauth.com",
	},
}

// OAuth clients configured by the customer
type OAuthClientConfiguration struct {
	clientId     string
	clientSecret string
}

// https://server.com/.well-known/openid-configuration

type ProvidersResponse struct {
	Provider      string `json:"provider"`
	LoginEndpoint string `json:"login_endpoint"`
}

type TokenEndpointResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	response := []ProvidersResponse{}

	for k, _ := range configuredProviders {
		response = append(response, ProvidersResponse{
			Provider:      string(k),
			LoginEndpoint: fmt.Sprintf("/auth/login?provider=%s", k),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

}
func loginHandler(w http.ResponseWriter, r *http.Request) {

	p := r.URL.Query().Get("provider")
	provider := Issuer(p)
	oauth, _, err := MakeOAuthProvider(provider, configuredProviders[provider])
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	oauthStateString := uniuri.New()
	url := oauth.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, currSchema *proto.Schema) {
	p := r.URL.Query().Get("provider")
	provider := Issuer(p)
	oauth, isOidc, err := MakeOAuthProvider(provider, configuredProviders[provider])
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	code := r.FormValue("code")

	token, err := oauth.Exchange(context.Background(), code)
	if !token.Valid() {
		fmt.Fprintln(w, err.Error())
		return
	}

	if !token.Valid() {
		fmt.Fprintln(w, "Invalid token!")
		return
	}

	if isOidc {
		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			//
			fmt.Fprintln(w, "handle missing token")
			return
		}

		oidcProv, err := oidc.NewProvider(context.Background(), oidcIssuers[provider].issuer)
		if err != nil {
			fmt.Fprintln(w, err.Error())
			return
		}

		var verifier = oidcProv.Verifier(&oidc.Config{
			ClientID: oauth.ClientID,
		})

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			fmt.Fprintln(w, err.Error())
			return
		}

		// Extract  claims
		var claims struct {
			Subject  string `json:"sub"`
			Email    string `json:"email,omitempty"`
			Verified bool   `json:"email_verified,omitempty"`
			Name     string `json:"name,omitempty"` // todo
		}
		if err := idToken.Claims(&claims); err != nil {
			// handle error
			fmt.Fprintln(w, err.Error())
			return
		}

		identity, err := actions.FindIdentityByExternalId(ctx, currSchema, claims.Subject, oidcIssuers[provider].issuer)
		if identity == nil {
			identity, err = actions.CreateExternalIdentityN(ctx, currSchema, claims.Subject, oidcIssuers[provider].issuer, rawIDToken, claims.Name, claims.Email)
		}

		btoken, err := actions.GenerateBearerToken(ctx, identity.Id)
		if err != nil {
			fmt.Fprintln(w, err.Error())
			return
		}

		// todo: refresh token rotation, see https://developer.okta.com/docs/guides/refresh-tokens/main/#about-refresh-tokens
		// Note: When a refresh token is rotated, the new refresh_token string in the response has a different value than the previous refresh_token string due to security concerns with single-page apps. However, the expiration date remains the same. The lifetime is inherited from the initial refresh token minted when the user first authenticates.
		// NOTE AGAIN:  rotating refresh tokens may means we dont require PKCE: https://datatracker.ietf.org/doc/html/rfc6749#section-10.4
		rtoken := uniuri.New() //actions.GenerateRefreshToken(ctx, identity.Id)
		if err != nil {
			fmt.Fprintln(w, err.Error())
			return
		}

		response := TokenEndpointResponse{
			AccessToken:  btoken,
			TokenType:    "bearer",
			RefreshToken: rtoken,
			ExpiresIn:    123,
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		// if newToken.AccessToken != token.AccessToken {
		// 	SaveToken(newToken)
		// 	log.Println("Saved new token:", newToken.AccessToken)
		// }

		return

	} else if provider == GitHub {
		// If Github, then we manually get userinfo (because it doesn't follow the openid spec)
		// there is no id token

		req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
		if err != nil {
			//return  err
		}

		req.Header.Set("Authorization", "token "+token.AccessToken)

		client := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
		resp, err := client.Do(req)
		if err != nil {
			//return []byte{}, cacheHit, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			//return []byte{}, cacheHit, err
		}

		if resp.StatusCode != http.StatusOK {
			//return nil, false, fmt.Errorf("failed to fetch url: %s  Status: %d  ", req.URL.String(), resp.StatusCode)
		}

		fmt.Fprintln(w, string(body))

		userInfo := &GitHubUserInfo{}
		err = json.Unmarshal(body, userInfo)
		if err != nil {
			//return nil, fmt.Errorf("Failed to unmarshal: %s", err)
		}

		// if user is null, it's because it is not public
		// now need to get private emails from here:
		// https://stackoverflow.com/questions/35373995/github-user-email-is-null-despite-useremail-scope

		fmt.Fprintln(w, userInfo)
	}
}

type GitHubUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func tokenHandler(ctx context.Context, rw http.ResponseWriter, r *http.Request, currSchema *proto.Schema) {
	// handle grants:
	//  - password grant?
	//  - refresh grant
	//  - token exchange grant

	// configuration for token exchange
	//  - token exchange OIDC issuers
	//  - create if not exists

	// Auth0 exposes a JWKS endpoint for each tenant, which is found at https://{yourDomain}/.well-known/jwks.json. This endpoint will contain the JWK used to verify all Auth0-issued JWTs for this tenant.

	if r.Method != "POST" {
		fmt.Fprintln(rw, "must be POST")
		return
		//return accessRequest, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "refresh_token":
		refreshToken := r.Form.Get("refresh_token")
		if refreshToken == "" {
			fmt.Fprintln(rw, "refresh_token required for this grant type")
			return
		}

		subject, _, _ := actions.ValidateRefreshToken(ctx, refreshToken)

		// Check that identity hasn't been revoked access somehow
		_, _ = actions.FindIdentityById(ctx, currSchema, subject)

		token, _ := actions.GenerateBearerToken(ctx, subject)
		refresh, _ := actions.GenerateRefreshToken(ctx, subject)

		response := TokenEndpointResponse{
			AccessToken:  token,
			TokenType:    "bearer",
			RefreshToken: refresh,
			ExpiresIn:    123,
		}

		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(response)

	case "token_exchange":
		//id token stuff
	case "":
		fmt.Fprintln(rw, "grant_type required")
		return
	default:
		fmt.Fprintln(rw, "unsupported grant type")
		return
	}
}

// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

// All other Claims carry no such guarantees across different issuers in terms of stability over time or uniqueness across users, and Issuers are permitted to apply local restrictions and policies. For instance, an Issuer MAY re-use an email Claim Value across different End-Users at different points in time, and the claimed email address for a given End-User MAY change over time. Therefore, other Claims such as email, phone_number, and preferred_username and MUST NOT be used as unique identifiers for the End-User.

// https://oauth.net/articles/authentication/

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
	Gender        string `json:"gender"`
	Locale        string `json:"locale"`
}

func NewHandler(s *proto.Schema) common.ApiHandlerFunc {
	handlers := map[string]common.ApiHandlerFunc{}

	for _, api := range s.Apis {
		root := "/" + strings.ToLower(api.Name)

		handlers[root+"/graphql"] = graphql.NewHandler(s, api)
		handlers[root+"/rpc"] = jsonrpc.NewHandler(s, api)

		httpJson := httpjson.NewHandler(s, api)
		for _, name := range proto.GetActionNamesForApi(s, api) {
			handlers[root+"/json/"+strings.ToLower(name)] = httpJson
		}
		handlers[root+"/json/openapi.json"] = httpJson
	}

	return withRequestResponseLogging(func(r *http.Request) common.Response {
		handler, ok := handlers[strings.ToLower(r.URL.Path)]
		if !ok {
			return common.Response{
				Status: 404,
				Body:   []byte("Not found"),
			}
		}

		return handler(r)
	})
}

type JobHandler struct {
	schema *proto.Schema
}

func NewJobHandler(currSchema *proto.Schema) JobHandler {
	return JobHandler{
		schema: currSchema,
	}
}

// RunJob will run the job function in the runtime.
func (handler JobHandler) RunJob(ctx context.Context, jobName string, inputs map[string]any, trigger functions.TriggerType) error {
	ctx, span := tracer.Start(ctx, "Run job")
	defer span.End()

	job := proto.FindJob(handler.schema.Jobs, strcase.ToCamel(jobName))
	if job == nil {
		return fmt.Errorf("no job with the name '%s' exists", jobName)
	}

	scope := actions.NewJobScope(ctx, job, handler.schema)
	permissionState := common.NewPermissionState()

	if trigger == functions.ManualTrigger {
		// Check if authorisation can be achieved early.
		canAuthoriseEarly, authorised, err := actions.TryResolveAuthorisationEarly(scope, job.Permissions)
		if err != nil {
			return err
		}

		if canAuthoriseEarly {
			if authorised {
				permissionState.Grant()
			} else {
				return common.NewPermissionError()
			}
		}
	}

	err := functions.CallJob(
		ctx,
		job,
		inputs,
		permissionState,
		trigger,
	)

	// Generate and send any events for this context.
	// This must run regardless of the job succeeding or failing.
	// Failure to generate events fail silently.
	eventsErr := events.SendEvents(ctx, scope.Schema)
	if eventsErr != nil {
		span.RecordError(eventsErr)
		span.SetStatus(codes.Error, eventsErr.Error())
	}

	return err
}

type SubscriberHandler struct {
	schema *proto.Schema
}

func NewSubscriberHandler(currSchema *proto.Schema) SubscriberHandler {
	return SubscriberHandler{
		schema: currSchema,
	}
}

// RunSubscriber will run the subscriber function in the runtime with the event payload.
func (handler SubscriberHandler) RunSubscriber(ctx context.Context, subscriberName string, event *events.Event) error {
	ctx, span := tracer.Start(ctx, "Run subscriber")
	defer span.End()

	subscriber := proto.FindSubscriber(handler.schema.Subscribers, subscriberName)
	if subscriber == nil {
		return fmt.Errorf("no subscriber with the name '%s' exists", subscriberName)
	}

	err := functions.CallSubscriber(
		ctx,
		subscriber,
		event,
	)

	// Generate and send any events for this context.
	// This must run regardless of the function succeeding or failing.
	// Failure to generate events fail silently.
	eventsErr := events.SendEvents(ctx, handler.schema)
	if eventsErr != nil {
		span.RecordError(eventsErr)
		span.SetStatus(codes.Error, eventsErr.Error())
	}

	return err
}

func withRequestResponseLogging(handler common.ApiHandlerFunc) common.ApiHandlerFunc {
	return func(request *http.Request) common.Response {
		log.WithFields(log.Fields{
			"url":     request.URL,
			"uri":     request.RequestURI,
			"headers": request.Header,
			"method":  request.Method,
			"host":    request.Host,
		})

		response := handler(request)

		entry := log.WithFields(log.Fields{
			"headers": response.Headers,
			"status":  response.Status,
		})
		if response.Status >= 300 {
			entry.WithField("body", string(response.Body))
		}
		entry.Info("response")

		return response
	}
}

func logLevel() log.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "trace":
		return log.TraceLevel
	case "debug":
		return log.DebugLevel
	case "info":
		return log.InfoLevel
	case "warn":
		return log.WarnLevel
	case "error":
		return log.ErrorLevel
	default:
		return log.ErrorLevel
	}
}
