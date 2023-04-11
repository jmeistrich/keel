package program

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/radovskyb/watcher"
	"github.com/rs/cors"
	"github.com/teamkeel/keel/cmd/cliconfig"
	"github.com/teamkeel/keel/cmd/database"
	"github.com/teamkeel/keel/config"
	"github.com/teamkeel/keel/db"
	"github.com/teamkeel/keel/exporter"
	"github.com/teamkeel/keel/migrations"
	"github.com/teamkeel/keel/node"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema"
	"github.com/teamkeel/keel/schema/reader"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type LoadSchemaMsg struct {
	Schema      *proto.Schema
	Config      *config.ProjectConfig
	SchemaFiles []reader.SchemaFile
	Secrets     map[string]string
	Err         error
}

func LoadSchema(dir, environment string) tea.Cmd {
	return func() tea.Msg {
		b := schema.Builder{}
		s, err := b.MakeFromDirectory(dir)

		absolutePath, filepathErr := filepath.Abs(dir)
		if filepathErr != nil {
			err = filepathErr
		}

		cliConfig := cliconfig.New(&cliconfig.Options{
			WorkingDir: dir,
		})

		secrets, configErr := cliConfig.GetSecrets(absolutePath, environment)
		if configErr != nil {
			err = configErr
		}

		if b.Config == nil {
			b.Config = &config.ProjectConfig{}
		}

		invalid, invalidSecrets := b.Config.ValidateSecrets(secrets)
		if invalid {
			err = fmt.Errorf("missing secrets from local config in ~/.keel/config.yaml: %s", strings.Join(invalidSecrets, ", "))
		}

		msg := LoadSchemaMsg{
			Schema:      s,
			Config:      b.Config,
			SchemaFiles: b.SchemaFiles(),
			Secrets:     secrets,
			Err:         err,
		}

		return msg
	}
}

type ScaffoldMsg struct {
	Err            error
	GeneratedFiles node.GeneratedFiles
}

func Scaffold(dir string) tea.Cmd {
	return func() tea.Msg {
		files, err := node.Scaffold(dir)

		if err != nil {
			return ScaffoldMsg{
				Err: err,
			}
		}
		return ScaffoldMsg{
			GeneratedFiles: files,
		}
	}
}

type StartDatabaseMsg struct {
	ConnInfo *db.ConnectionInfo
	Err      error
}

func StartDatabase(reset bool, mode int) tea.Cmd {
	return func() tea.Msg {
		connInfo, err := database.Start(!reset)
		if err != nil {
			return StartDatabaseMsg{
				Err: err,
			}
		}

		if mode != ModeTest {
			return StartDatabaseMsg{
				ConnInfo: connInfo,
			}
		}

		mainDB, err := sql.Open("postgres", connInfo.String())
		if err != nil {
			return StartDatabaseMsg{
				Err: err,
			}
		}

		_, err = mainDB.Exec(`
			DROP DATABASE IF EXISTS keel_test
		`)
		if err != nil {
			return StartDatabaseMsg{
				Err: err,
			}
		}

		_, err = mainDB.Exec(`
			CREATE DATABASE keel_test
		`)
		if err != nil {
			return StartDatabaseMsg{
				Err: err,
			}
		}

		return StartDatabaseMsg{
			ConnInfo: connInfo.WithDatabase("keel_test"),
		}
	}
}

type SetupFunctionsMsg struct {
	Err error
}

func SetupFunctions(dir string, nodePackagesPath string) tea.Cmd {
	return func() tea.Msg {
		err := node.Bootstrap(dir, node.WithPackagesPath(nodePackagesPath))
		if err != nil {
			return SetupFunctionsMsg{
				Err: err,
			}
		}
		return SetupFunctionsMsg{}
	}
}

type UpdateFunctionsMsg struct {
	Err error
}

type TypeScriptError struct {
	Output string
	Err    error
}

func (t *TypeScriptError) Error() string {
	return fmt.Sprintf("TypeScript error: %s", t.Err.Error())
}

func UpdateFunctions(dir string) tea.Cmd {
	return func() tea.Msg {
		files, err := node.Generate(context.TODO(), dir, node.WithDevelopmentServer(true))
		if err != nil {
			return UpdateFunctionsMsg{Err: err}
		}

		err = files.Write()
		if err != nil {
			return UpdateFunctionsMsg{Err: err}
		}

		cmd := exec.Command("npx", "tsc", "--noEmit", "--pretty")
		cmd.Dir = dir

		b, err := cmd.CombinedOutput()
		if err != nil {
			return UpdateFunctionsMsg{
				Err: &TypeScriptError{
					Output: string(b),
					Err:    err,
				},
			}
		}

		return UpdateFunctionsMsg{}
	}
}

type RunMigrationsMsg struct {
	Err     error
	Changes []*migrations.DatabaseChange
}

type ApplyMigrationsError struct {
	Err error
}

func (a *ApplyMigrationsError) Error() string {
	return a.Err.Error()
}

func RunMigrations(schema *proto.Schema, connInfo *db.ConnectionInfo) tea.Cmd {
	return func() tea.Msg {
		db, err := db.New(context.Background(), connInfo)
		if err != nil {
			return RunMigrationsMsg{
				Err: err,
			}
		}

		currSchema, err := migrations.GetCurrentSchema(context.Background(), db)
		if err != nil {
			return RunMigrationsMsg{
				Err: err,
			}
		}

		m := migrations.New(schema, currSchema)

		msg := RunMigrationsMsg{
			Changes: m.Changes,
		}

		if !m.HasModelFieldChanges() {
			return msg
		}

		err = m.Apply(context.Background(), db)
		if err != nil {
			msg.Err = &ApplyMigrationsError{
				Err: err,
			}
		}

		return msg
	}
}

type StartFunctionsMsg struct {
	Err    error
	Server *node.DevelopmentServer
}

type StartFunctionsError struct {
	Err    error
	Output string
}

func (s *StartFunctionsError) Error() string {
	return s.Err.Error()
}

type FunctionsOutputMsg struct {
	Output string
}

func StartFunctions(dir string, mode int, cfg *config.ProjectConfig, connInfo *db.ConnectionInfo, ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		envType := "development"
		if mode == ModeTest {
			envType = "test"
		}

		envVars := cfg.GetEnvVars(envType)
		envVars["KEEL_DB_CONN_TYPE"] = "pg"
		envVars["KEEL_DB_CONN"] = connInfo.String()

		output := &FunctionsOutputWriter{
			// Initially buffer output inside the writer in case there's an error
			Buffer: true,
			ch:     ch,
		}
		server, err := node.RunDevelopmentServer(dir, &node.ServerOpts{
			EnvVars: envVars,
			Output:  output,
		})
		if err != nil {
			return StartFunctionsMsg{
				Err: &StartFunctionsError{
					Output: strings.Join(output.Output, "\n"),
					Err:    err,
				},
			}
		}

		// Stop buffering output now we know the process started.
		// All future output will be written to the given channel
		output.Buffer = false

		return StartFunctionsMsg{
			Server: server,
		}
	}
}

type RuntimeRequestMsg struct {
	w    http.ResponseWriter
	r    *http.Request
	done chan bool
}

func StartRuntimeServer(port string, ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		runtimeServer := http.Server{
			Addr: fmt.Sprintf(":%s", port),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				done := make(chan bool, 1)
				ch <- RuntimeRequestMsg{
					w:    w,
					r:    r,
					done: done,
				}
				<-done
			}),
		}
		_ = runtimeServer.ListenAndServe()
		return nil
	}
}

type RpcRequestMsg struct {
	w    http.ResponseWriter
	r    *http.Request
	done chan bool
}

func StartRpcServer(port string, ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		rpcServer := http.Server{
			Addr: fmt.Sprintf(":%s", port),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				done := make(chan bool, 1)
				ch <- RpcRequestMsg{
					w:    w,
					r:    r,
					done: done,
				}
				<-done
			}),
		}
		_ = rpcServer.ListenAndServe()
		return nil
	}
}

func StartTraceServer(port string) tea.Cmd {
	return func() tea.Msg {
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

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/traces":
				w.Header().Set("Content-Type", "application/json")
				traceData := exporter.AllTraces()

				res := []tracetest.SpanStub{}

				for _, v := range traceData {
					for _, span := range v {
						if !span.Parent.HasSpanID() {
							res = append(res, span)
						}
					}
				}

				b, err := json.Marshal(res)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write(b)
			case "/trace":
				id := r.URL.Query().Get("id")
				if id == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				trace := exporter.GetTrace(id)
				b, err := json.Marshal(trace)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write(b)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})

		traceServer := http.Server{
			Addr:    fmt.Sprintf(":%s", port),
			Handler: cors.Handler(handler),
		}

		_ = traceServer.ListenAndServe()
		return nil
	}
}

type FunctionsOutputWriter struct {
	Output []string
	Buffer bool
	ch     chan tea.Msg
}

func (f *FunctionsOutputWriter) Write(p []byte) (n int, err error) {
	str := string(p)
	lines := strings.Split(str, "\n")

	for _, line := range lines {
		if f.Buffer {
			f.Output = append(f.Output, line)
		} else {
			f.ch <- FunctionsOutputMsg{
				Output: line,
			}
		}
	}

	return len(p), nil
}

type WatcherMsg struct {
	Err   error
	Path  string
	Event string
}

func StartWatcher(dir string, ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		w := watcher.New()
		w.SetMaxEvents(1)
		w.FilterOps(watcher.Write, watcher.Remove)

		ignored := []string{
			"node_modules/",
			".build/",
		}

		w.AddFilterHook(func(info os.FileInfo, fullPath string) error {
			for _, v := range ignored {
				if strings.Contains(fullPath, v) {
					return watcher.ErrSkip
				}
			}

			return nil
		})

		go func() {
			for {
				select {
				case event := <-w.Event:
					ch <- WatcherMsg{
						Path:  event.Path,
						Event: event.Op.String(),
					}
				case <-w.Closed:
					return
				}
			}
		}()

		err := w.AddRecursive(dir)
		if err != nil {
			return WatcherMsg{
				Err: err,
			}
		}

		_ = w.Start(time.Millisecond * 100)
		return nil
	}
}

type RunTestsMsg struct {
	Err    error
	Output string
}

func RunTests(dir string, port string, cfg *config.ProjectConfig, conn *db.ConnectionInfo, pattern string) tea.Cmd {
	return func() tea.Msg {
		args := []string{
			"vitest",
			"run",
			"--color",
			"--reporter", "verbose",
			"--config", "./.build/vitest.config.mjs",
		}

		if pattern != "" {
			args = append(args, "--testNamePattern", pattern)
		}

		cmd := exec.Command("npx", args...)
		cmd.Dir = dir
		cmd.Env = os.Environ()

		envVars := cfg.GetEnvVars("test")
		envVars["KEEL_TESTING_ACTIONS_API_URL"] = fmt.Sprintf("http://localhost:%s/testingactionsapi/json", port)
		envVars["KEEL_DB_CONN_TYPE"] = "pg"
		envVars["KEEL_DB_CONN"] = conn.String()
		envVars["NODE_OPTIONS"] = "--no-warnings"

		for key, value := range envVars {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}

		b, err := cmd.CombinedOutput()
		return RunTestsMsg{
			Output: string(b),
			Err:    err,
		}
	}
}

// LoadSecrets lists secrets from the given file and returns a command
func LoadSecrets(path, environment string) (map[string]string, error) {
	projectPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	config := cliconfig.New(&cliconfig.Options{
		WorkingDir: projectPath,
	})

	secrets, err := config.GetSecrets(path, environment)
	if err != nil {
		return nil, err

	}
	return secrets, nil
}

func SetSecret(path, environment, key, value string) error {
	projectPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	config := cliconfig.New(&cliconfig.Options{
		WorkingDir: projectPath,
	})

	return config.SetSecret(path, environment, key, value)
}

func RemoveSecret(path, environment, key string) error {
	projectPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	config := cliconfig.New(&cliconfig.Options{
		WorkingDir: projectPath,
	})

	return config.RemoveSecret(path, environment, key)
}
