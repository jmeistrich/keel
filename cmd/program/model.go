package program

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql/playground"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/cors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/teamkeel/keel/cmd/database"
	"github.com/teamkeel/keel/config"
	"github.com/teamkeel/keel/db"
	"github.com/teamkeel/keel/exporter"
	"github.com/teamkeel/keel/functions"
	"github.com/teamkeel/keel/migrations"
	"github.com/teamkeel/keel/node"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/rpc/rpc"
	rpcApiServer "github.com/teamkeel/keel/rpc/server"
	"github.com/teamkeel/keel/runtime"
	"github.com/teamkeel/keel/runtime/runtimectx"
	"github.com/teamkeel/keel/schema/reader"
	"github.com/twitchtv/twirp"
)

const (
	ModeValidate = iota
	ModeRun
	ModeTest
	ModeScaffold
)

const (
	StatusSetupDatabase = iota
	StatusSetupFunctions
	StatusLoadSchema
	StatusRunMigrations
	StatusUpdateFunctions
	StatusStartingFunctions
	StatusRunning
	StatusQuitting
	StatusScaffolded
)

func Run(model *Model) {
	// The runtime currently does logging with logrus, which is super noisy.
	// For now we just discard the logs as they are not useful in the CLI
	logrus.SetOutput(io.Discard)

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
	Port      string
	RpcPort   string
	TracePort string

	// If true then the database will be reset. Only
	// applies to ModeRun.
	ResetDatabase bool

	// If set then @teamkeel/* npm packages will be installed
	// from this path, rather than NPM.
	NodePackagesPath string

	// Pattern to pass to vitest to isolate specific tests
	TestPattern string

	// Model state - used in View()
	Status           int
	Err              error
	Schema           *proto.Schema
	Config           *config.ProjectConfig
	SchemaFiles      []reader.SchemaFile
	DatabaseConnInfo *db.ConnectionInfo
	GeneratedFiles   node.GeneratedFiles
	MigrationChanges []*migrations.DatabaseChange
	FunctionsServer  *node.DevelopmentServer
	RuntimeHandler   http.Handler
	RpcHandler       http.Handler
	RpcServer        *rpcApiServer.Server
	RuntimeRequests  []*RuntimeRequest
	FunctionsLog     []*FunctionLog
	TestOutput       string
	Secrets          map[string]string
	Environment      string

	// Channels for communication between long-running
	// commands and the Bubbletea program
	runtimeRequestsCh chan tea.Msg
	rpcRequestsCh     chan tea.Msg
	traceRequestsCh   chan tea.Msg
	functionsLogCh    chan tea.Msg
	watcherCh         chan tea.Msg
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
	m.rpcRequestsCh = make(chan tea.Msg, 1)
	m.functionsLogCh = make(chan tea.Msg, 1)
	m.watcherCh = make(chan tea.Msg, 1)
	m.Environment = lo.Ternary(m.Mode == ModeTest, "test", "development")
	m.RpcServer = &rpcApiServer.Server{}
	m.RpcPort = "8001"
	m.TracePort = "8002"

	switch m.Mode {
	case ModeValidate:
		m.Status = StatusLoadSchema
		return LoadSchema(m.ProjectDir, m.Environment)
	case ModeScaffold:
		m.Status = StatusLoadSchema
		return LoadSchema(m.ProjectDir, m.Environment)
	case ModeRun, ModeTest:
		m.Status = StatusSetupDatabase
		return StartDatabase(m.ResetDatabase, m.Mode)
	default:
		return nil
	}
}

func NextMsgCommand(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.Status = StatusQuitting
			return m, tea.Quit
		}

	case StartDatabaseMsg:
		m.DatabaseConnInfo = msg.ConnInfo
		m.Err = msg.Err

		// If the database can't be started we exit
		if m.Err != nil {
			return m, tea.Quit
		}

		m.Status = StatusSetupFunctions
		return m, SetupFunctions(m.ProjectDir, m.NodePackagesPath)

	case SetupFunctionsMsg:
		m.Err = msg.Err

		// If something failed here (most likely npm install) we exit
		if m.Err != nil {
			return m, tea.Quit
		}

		m.Status = StatusLoadSchema

		cmds := []tea.Cmd{
			StartRuntimeServer(m.Port, m.runtimeRequestsCh),
			StartRpcServer(m.RpcPort, m.rpcRequestsCh),
			StartTraceServer(m.TracePort),
			NextMsgCommand(m.runtimeRequestsCh),
			NextMsgCommand(m.rpcRequestsCh),
			LoadSchema(m.ProjectDir, m.Environment),
		}

		if m.Mode == ModeRun {
			cmds = append(
				cmds,
				StartWatcher(m.ProjectDir, m.watcherCh),
				NextMsgCommand(m.watcherCh),
			)
		}

		return m, tea.Batch(cmds...)
	case ScaffoldMsg:
		m.GeneratedFiles = msg.GeneratedFiles
		m.Status = StatusScaffolded
		return m, tea.Quit
	case LoadSchemaMsg:
		m.Schema = msg.Schema
		m.SchemaFiles = msg.SchemaFiles
		m.Config = msg.Config
		m.Err = msg.Err
		m.Secrets = msg.Secrets

		if m.Mode == ModeScaffold {
			return m, Scaffold(m.ProjectDir)
		}

		// For validate mode we're done
		if m.Mode == ModeValidate {
			return m, tea.Quit
		}

		if m.Err != nil {
			if m.Mode == ModeTest {
				return m, tea.Quit
			}
			return m, nil
		}

		// For test mode inject a special API that contains all models
		// This is so in tests we can invoke any action
		if m.Mode == ModeTest {
			testApi := &proto.Api{
				Name: "TestingActionsApi",
			}
			for _, m := range m.Schema.Models {
				testApi.ApiModels = append(testApi.ApiModels, &proto.ApiModel{
					ModelName: m.Name,
				})
			}

			m.Schema.Apis = append(m.Schema.Apis, testApi)
		}

		// not really the place for this
		exporter, _ := exporter.New(exporter.WithPrettyPrint())
		_ = runtime.SetExporter(exporter)

		m.RuntimeHandler = runtime.NewHttpHandler(m.Schema)
		m.RpcHandler = rpc.NewAPIServer(m.RpcServer, twirp.WithServerPathPrefix("/rpc"))
		m.Status = StatusRunMigrations
		return m, RunMigrations(m.Schema, m.DatabaseConnInfo)

	case RunMigrationsMsg:
		m.Err = msg.Err
		m.MigrationChanges = msg.Changes

		if m.Err != nil {
			if m.Mode == ModeTest {
				return m, tea.Quit
			}
			return m, nil
		}

		if m.Mode == ModeRun && !node.HasFunctions(m.Schema) {
			m.Status = StatusRunning
			return m, nil
		}

		m.Status = StatusUpdateFunctions
		return m, UpdateFunctions(m.ProjectDir)

	case UpdateFunctionsMsg:
		m.Err = msg.Err
		if m.Err != nil {
			if m.Mode == ModeTest {
				return m, tea.Quit
			}
			return m, nil
		}

		if m.FunctionsServer != nil {
			_ = m.FunctionsServer.Kill()
		}

		if m.Mode == ModeTest && !node.HasFunctions(m.Schema) {
			m.Status = StatusRunning
			return m, RunTests(m.ProjectDir, m.Port, m.Config, m.DatabaseConnInfo, m.TestPattern)
		}

		m.Status = StatusStartingFunctions
		return m, tea.Batch(
			StartFunctions(m.ProjectDir, m.Mode, m.Config, m.DatabaseConnInfo, m.functionsLogCh),
			NextMsgCommand(m.functionsLogCh),
		)

	case StartFunctionsMsg:
		m.Err = msg.Err
		m.FunctionsServer = msg.Server
		m.Status = StatusRunning

		if m.Mode == ModeTest {
			return m, RunTests(m.ProjectDir, m.Port, m.Config, m.DatabaseConnInfo, m.TestPattern)
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

		if m.Mode == ModeRun || m.Mode == ModeTest {
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
			if !strings.HasSuffix(request.Path, "/openapi.json") {
				cmds = append(cmds, tea.Println(renderRequestLog(request)))
			}
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

		database, _ := db.New(ctx, m.DatabaseConnInfo)
		ctx = runtimectx.WithDatabase(ctx, database)
		ctx = runtimectx.WithSecrets(ctx, m.Secrets)
		if m.FunctionsServer != nil {
			ctx = functions.WithFunctionsTransport(
				ctx,
				functions.NewHttpTransport(m.FunctionsServer.URL),
			)
		}
		r = msg.r.WithContext(ctx)

		envVars := m.Config.GetEnvVars(lo.Ternary(m.Mode == ModeTest, "test", "development"))
		for k, v := range envVars {
			os.Setenv(k, v)
		}

		m.RuntimeHandler.ServeHTTP(msg.w, r)

		for k := range envVars {
			os.Unsetenv(k)
		}

		msg.done <- true
		return m, tea.Batch(cmds...)
	case RpcRequestMsg:
		ctx := msg.r.Context()
		ctx = context.WithValue(ctx, "schema", m.Schema)
		r := msg.r.WithContext(ctx)
		w := msg.w

		cmds := []tea.Cmd{
			NextMsgCommand(m.rpcRequestsCh),
		}

		if m.RpcHandler == nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("Cannot serve requests while there are schema errors. Please see the CLI output for more info."))
			msg.done <- true
			return m, NextMsgCommand(m.runtimeRequestsCh)
		}

		cors := cors.New(cors.Options{
			AllowedOrigins: []string{"*"},
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
		cors.Handler(m.RpcHandler).ServeHTTP(msg.w, r)
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

	case RunTestsMsg:
		m.Err = msg.Err
		m.TestOutput = msg.Output
		return m, tea.Quit
	}

	return m, nil
}

func (m *Model) View() string {
	b := strings.Builder{}

	// Mode specific output
	switch m.Mode {
	case ModeRun:
		b.WriteString(renderRun(m))
	case ModeValidate:
		b.WriteString(renderValidate(m))
	case ModeTest:
		b.WriteString(renderTest(m))
	case ModeScaffold:
		b.WriteString(renderScaffold(m))
	}

	if m.Err != nil {
		b.WriteString(renderError(m))
	}

	// The final "\n" is important as when Bubbletea exists it resets the last
	// line of output, meaning without a new line we'd lose the final line
	return b.String() + "\n"
}
