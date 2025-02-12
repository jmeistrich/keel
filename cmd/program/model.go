package program

import (
	"context"
	"crypto/rsa"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql/playground"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/teamkeel/keel/cmd/database"
	"github.com/teamkeel/keel/codegen"
	"github.com/teamkeel/keel/config"
	"github.com/teamkeel/keel/db"
	"github.com/teamkeel/keel/events"
	"github.com/teamkeel/keel/functions"
	"github.com/teamkeel/keel/mail"
	"github.com/teamkeel/keel/migrations"
	"github.com/teamkeel/keel/node"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/runtime"
	"github.com/teamkeel/keel/runtime/runtimectx"
	"github.com/teamkeel/keel/schema/reader"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	ModeRun = iota
)

const (
	StatusCheckingDependencies = iota
	StatusParsePrivateKey
	StatusSetupDatabase
	StatusSetupFunctions
	StatusLoadSchema
	StatusRunMigrations
	StatusUpdateFunctions
	StatusStartingFunctions
	StatusRunning
	StatusQuitting
)

func Run(model *Model) {
	// The runtime currently does logging with logrus, which is super noisy.
	// For now we just discard the logs as they are not useful in the CLI
	logrus.SetOutput(io.Discard)

	if model.TracingEnabled {
		exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithInsecure())
		if err != nil {
			panic(err)
		}

		provider := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(
				resource.NewSchemaless(attribute.String("service.name", "runtime")),
			),
		)

		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagation.TraceContext{})
	} else {
		// We still need a tracing provider for auditing and events,
		// even if the data is not being exported.
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
	}

	defer func() {
		_ = database.Stop()
		if model.FunctionsServer != nil {
			_ = model.FunctionsServer.Kill()
		}
	}()

	_, err := tea.NewProgram(model).Run()
	if err != nil {
		panic(err)
	}

	if model.Err != nil {
		os.Exit(1)
	}
}

type Model struct {
	// The directory of the Keel project
	ProjectDir string

	// The mode the Model is running in
	Mode int

	// Port to run the runtime server on in ModeRun
	Port string

	// If true then the database will be reset. Only
	// applies to ModeRun.
	ResetDatabase bool

	// If set then @teamkeel/* npm packages will be installed
	// from this path, rather than NPM.
	NodePackagesPath string

	// Either 'npm' or 'pnpm'
	PackageManager string

	// If set then runtime will be configured with private key
	// located at this path in pem format.
	PrivateKeyPath string

	// The private key to configure on runtime, or nil.
	PrivateKey *rsa.PrivateKey

	// Pattern to pass to vitest to isolate specific tests
	TestPattern string

	// If true then an OTLP export will be setup for the runtime and the
	// env var KEEL_TRACING_ENABLED will be passed to the functions runtime
	TracingEnabled bool

	// Model state - used in View()
	Status            int
	Err               error
	Schema            *proto.Schema
	Config            *config.ProjectConfig
	SchemaFiles       []*reader.SchemaFile
	Database          db.Database
	DatabaseConnInfo  *db.ConnectionInfo
	GeneratedFiles    codegen.GeneratedFiles
	MigrationChanges  []*migrations.DatabaseChange
	FunctionsServer   *node.DevelopmentServer
	RuntimeHandler    http.Handler
	JobHandler        runtime.JobHandler
	SubscriberHandler runtime.SubscriberHandler
	RuntimeRequests   []*RuntimeRequest
	FunctionsLog      []*FunctionLog
	TestOutput        string
	Secrets           map[string]string
	Environment       string

	// Channels for communication between long-running
	// commands and the Bubbletea program
	runtimeRequestsCh chan tea.Msg
	functionsLogCh    chan tea.Msg
	watcherCh         chan tea.Msg

	// Maintain the current dimensions of the user's terminal
	width  int
	height int
}

type RuntimeRequest struct {
	Time   time.Time
	Method string
	Path   string
}

type FunctionLog struct {
	Time  time.Time
	Value string
}

var _ tea.Model = &Model{}

func (m *Model) Init() tea.Cmd {
	m.runtimeRequestsCh = make(chan tea.Msg, 1)
	m.functionsLogCh = make(chan tea.Msg, 1)
	m.watcherCh = make(chan tea.Msg, 1)
	m.Environment = "development"

	m.Status = StatusCheckingDependencies
	return CheckDependencies()
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.Status = StatusQuitting
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		// This msg is sent once on program start
		// and then subsequently every time the user
		// resizes their terminal window.
		m.width = msg.Width
		m.height = msg.Height

		return m, nil
	case CheckDependenciesMsg:
		m.Err = msg.Err

		if m.Err != nil {
			return m, tea.Quit
		}

		m.Status = StatusSetupDatabase
		return m, StartDatabase(m.ResetDatabase, m.Mode, m.ProjectDir)
	case StartDatabaseMsg:
		m.DatabaseConnInfo = msg.ConnInfo
		m.Err = msg.Err

		// If the database can't be started we exit
		if m.Err != nil {
			return m, tea.Quit
		}

		database, err := db.New(context.Background(), m.DatabaseConnInfo.String())
		if err != nil {
			m.Err = err
			return m, tea.Quit
		}

		m.Database = database
		m.Status = StatusParsePrivateKey
		return m, ParsePrivateKey(m.PrivateKeyPath)
	case ParsePrivateKeyMsg:
		m.Err = msg.Err

		// If the private key can't be parsed we exit
		if m.Err != nil {
			return m, tea.Quit
		}

		m.PrivateKey = msg.PrivateKey

		m.Status = StatusSetupFunctions
		return m, SetupFunctions(m.ProjectDir, m.NodePackagesPath, m.PackageManager)
	case SetupFunctionsMsg:
		m.Err = msg.Err

		// If something failed here (most likely npm install) we exit
		if m.Err != nil {
			return m, tea.Quit
		}

		m.Status = StatusLoadSchema

		cmds := []tea.Cmd{
			StartRuntimeServer(m.Port, m.runtimeRequestsCh),
			NextMsgCommand(m.runtimeRequestsCh),
			LoadSchema(m.ProjectDir, m.Environment),
		}

		if m.Mode == ModeRun {
			cmds = append(
				cmds,
				StartWatcher(m.ProjectDir, m.watcherCh, nil),
				NextMsgCommand(m.watcherCh),
			)
		}

		return m, tea.Batch(cmds...)
	case LoadSchemaMsg:
		m.Schema = msg.Schema
		m.SchemaFiles = msg.SchemaFiles
		m.Config = msg.Config
		m.Err = msg.Err
		m.Secrets = msg.Secrets

		if m.Err != nil {
			return m, nil
		}

		cors := cors.New(cors.Options{
			AllowOriginFunc: func(origin string) bool {
				return true
			},
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodPut,
				http.MethodPatch,
				http.MethodDelete,
			},
			AllowedHeaders:   []string{"*"},
			AllowCredentials: true,
		})

		m.RuntimeHandler = cors.Handler(runtime.NewHttpHandler(m.Schema))
		m.Status = StatusRunMigrations
		return m, RunMigrations(m.Schema, m.Database)
	case RunMigrationsMsg:
		m.Err = msg.Err
		m.MigrationChanges = msg.Changes

		if m.Err != nil {
			return m, nil
		}

		if m.Mode == ModeRun && !node.HasFunctions(m.Schema) {
			m.Status = StatusRunning
			return m, nil
		}

		m.Status = StatusUpdateFunctions
		return m, UpdateFunctions(m.Schema, m.ProjectDir)

	case UpdateFunctionsMsg:
		m.Err = msg.Err
		if m.Err != nil {
			return m, nil
		}

		// If functions already running nothing to do
		if m.FunctionsServer != nil {
			_ = m.FunctionsServer.Rebuild()
			m.Status = StatusRunning
			return m, nil
		}

		// Start functions if needed
		if node.HasFunctions(m.Schema) {
			m.Status = StatusStartingFunctions
			return m, tea.Batch(
				StartFunctions(m),
				NextMsgCommand(m.functionsLogCh),
			)
		}

		return m, nil

	case StartFunctionsMsg:
		m.Err = msg.Err
		m.FunctionsServer = msg.Server

		if msg.Err == nil {
			m.Status = StatusRunning
		}

		return m, nil
	case FunctionsOutputMsg:
		log := &FunctionLog{
			Time:  time.Now(),
			Value: msg.Output,
		}
		m.FunctionsLog = append(m.FunctionsLog, log)

		cmds := []tea.Cmd{
			NextMsgCommand(m.functionsLogCh),
		}

		if m.Mode == ModeRun {
			cmds = append(cmds, tea.Println(renderFunctionLog(log)))
		}

		return m, tea.Batch(cmds...)
	case RuntimeRequestMsg:
		r := msg.r
		w := msg.w

		request := &RuntimeRequest{
			Time:   time.Now(),
			Method: r.Method,
			Path:   r.URL.Path,
		}

		cmds := []tea.Cmd{
			NextMsgCommand(m.runtimeRequestsCh),
		}

		m.RuntimeRequests = append(m.RuntimeRequests, request)

		// log runtime requests for the run cmd
		if m.Mode == ModeRun && m.Err == nil && m.Status >= StatusLoadSchema {
			cmds = append(cmds, tea.Println(renderRequestLog(request)))
		}

		if strings.HasSuffix(r.URL.Path, "/graphiql") {
			handler := playground.Handler("GraphiQL", strings.TrimSuffix(r.URL.Path, "/graphiql")+"/graphql")
			handler(w, r)
			msg.done <- true
			return m, NextMsgCommand(m.runtimeRequestsCh)
		}

		if m.RuntimeHandler == nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("Cannot serve requests while there are schema errors. Please see the CLI output for more info."))
			msg.done <- true
			return m, NextMsgCommand(m.runtimeRequestsCh)
		}

		ctx := msg.r.Context()

		if m.PrivateKey != nil {
			ctx = runtimectx.WithPrivateKey(ctx, m.PrivateKey)
		}

		ctx = db.WithDatabase(ctx, m.Database)
		ctx = runtimectx.WithSecrets(ctx, m.Secrets)
		ctx = runtimectx.WithOAuthConfig(ctx, &m.Config.Auth)

		mailClient := mail.NewSMTPClientFromEnv()
		if mailClient != nil {
			ctx = runtimectx.WithMailClient(ctx, mailClient)
		} else {
			ctx = runtimectx.WithMailClient(ctx, mail.NoOpClient())
		}

		if m.FunctionsServer != nil {
			ctx = functions.WithFunctionsTransport(
				ctx,
				functions.NewHttpTransport(m.FunctionsServer.URL),
			)
		}

		envVars := m.Config.GetEnvVars("development")
		for k, v := range envVars {
			os.Setenv(k, v)
		}

		// Synchronous event handling for keel run.
		// TODO: make asynchronous
		ctx, err := events.WithEventHandler(ctx, func(ctx context.Context, subscriber string, event *events.Event, traceparent string) error {
			return runtime.NewSubscriberHandler(m.Schema).RunSubscriber(ctx, subscriber, event)
		})
		if err != nil {
			m.Err = err
			return m, tea.Quit
		}

		// In run mode we accept any external issuers but the tokens need to be signed correctly
		ctx = runtimectx.WithAuthConfig(ctx, runtimectx.AuthConfig{
			AllowAnyIssuers: true,
		})

		r = msg.r.WithContext(ctx)
		m.RuntimeHandler.ServeHTTP(msg.w, r)

		for k := range envVars {
			os.Unsetenv(k)
		}

		msg.done <- true
		return m, tea.Batch(cmds...)
	case WatcherMsg:
		m.Err = msg.Err
		m.Status = StatusLoadSchema

		// If the watcher errors then probably best to exit
		if m.Err != nil {
			return m, tea.Quit
		}

		return m, tea.Batch(
			NextMsgCommand(m.watcherCh),
			LoadSchema(m.ProjectDir, m.Environment),
		)

	}

	return m, nil
}

func (m *Model) View() string {
	b := strings.Builder{}

	// lipgloss will automatically wrap any text based on the current dimensions of the user's term.
	s := lipgloss.
		NewStyle().
		MaxWidth(m.width).
		MaxHeight(m.height)

	// Mode specific output
	switch m.Mode {
	case ModeRun:
		b.WriteString(renderRun(m))
	}

	if m.Err != nil {
		b.WriteString(renderError(m))
	}

	// The final "\n" is important as when Bubbletea exists it resets the last
	// line of output, meaning without a new line we'd lose the final line
	return s.Render(b.String() + "\n")
}
