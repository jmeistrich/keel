package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/dchest/uniuri"
	"github.com/iancoleman/strcase"
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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

func NewHttpHandler(currSchema *proto.Schema) http.Handler {
	var handler common.ApiHandlerFunc
	if currSchema != nil {
		handler = NewHandler(currSchema)
	}

	authSetup()

	httpHandler := func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "Runtime")
		defer span.End()

		span.SetAttributes(
			attribute.String("runtime_version", Version),
		)

		if r.URL.Path == "/" {
			indexHandler(w, r)
			return
		} else if r.URL.Path == "/login" {
			loginHandler(w, r)
			return
		} else if r.URL.Path == "/callback" {
			callbackHandler(w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")

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

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8000/callback",
	ClientID:     "247884616520-ft5a4aerlpth1p10sao3rb7f92padugf.apps.googleusercontent.com",
	ClientSecret: "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",
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint: google.Endpoint,
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "<a href='/login'>Log in with Google</a>")

}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	oauthStateString := uniuri.New()
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	token, _ := googleOauthConfig.Exchange(oauth2.NoContext, code)
	fmt.Fprintf(w, token.AccessToken)

	response, _ := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	var user *GoogleUser
	_ = json.Unmarshal(contents, &user)

	fmt.Fprintf(w, "Email: %s\nName: %s\nImage link: %s\n", user.Email, user.Name, user.Picture)

}

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
