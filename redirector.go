package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Program name
const progName = "redirector"

// Project version set by GoReleaser
var version = "development"

// The configuration file path
var cfgFile string

// The default configuration file path
const cfgFileDefault = "/etc/redirector.yaml"

// The address and port to listen on
var addr string

// The default address and port to addr on
const defaultAddr = "127.0.0.1:8000"

// The log level
var logLevel string

// The default log level
const defaultLogLevel = "info"

// The log format
var logFormat string

// The default log format
const defaultLogFormat = "color"

// The root command defines the command line interface
var rootCmd = &cobra.Command{
	Use:     progName,
	Short:   "HTTP server that redirects requests.",
	Version: version,
	Run:     Serve,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", cfgFileDefault, "config file")
	rootCmd.Flags().StringVarP(&addr, "listen", "l", defaultAddr, "the address and port to listen on")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "L", defaultLogLevel, "the log level: trace/debug/info/warn/error/fatal/panic")
	rootCmd.Flags().StringVarP(&logFormat, "log-format", "F", defaultLogFormat, "the log format: color/nocolor/json")
	rootCmd.Flags().SortFlags = false
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Print an error message on stderr and exit with a non-zero code
func er(msg interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, "%v: %v\n", progName, msg)
	os.Exit(1)
}

func erf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	er(msg)
}

var accessLog zerolog.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
var errorLog zerolog.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

// Initialize the configuration
func initConfig() {
	// Set log format
	nocolor := false
	switch logFormat {
	case "json":
		// Nothing to do
	case "nocolor":
		nocolor = true
		fallthrough
	case "color":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
		accessLog = accessLog.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    nocolor,
			TimeFormat: "2006-01-02 15:04:05.999",
			PartsOrder: []string{
				zerolog.TimestampFieldName,
			},
		})
		errorLog = errorLog.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    nocolor,
			TimeFormat: "2006-01-02 15:04:05.999",
		})
	default:
		erf("Unknown log format: %v", logFormat)
	}

	// Set log level
	if level, err := zerolog.ParseLevel(logLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	} else {
		erf("Unknown log level: %v", logLevel)
	}

	// Load configuration
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(cfgFileDefault)
	}
	if err := viper.ReadInConfig(); err != nil {
		er(err)
	}

	// Watch configuration file and fire event
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		configurationLoaded()
	})
	configurationLoaded()
}

// The configuration
type Config struct {
	Redirections []Redirection `yaml:"redirs"`
}

// A redirection specification
type Redirection struct {
	Host   string   `yaml:"host,omitempty"`
	Hosts  []string `yaml:"hosts,omitempty"`
	Target string   `yaml:"target"`
	Status int      `yaml:"status,omitempty"`
}

// The redirection handler
var redirectHandler = RedirectHandler{}

// Called when the configuration is (re)loaded
func configurationLoaded() {
	var config Config
	if err := viper.Unmarshal(&config); err == nil {
		errorLog.Info().
			Msgf("Configuration loaded from file: %v", viper.ConfigFileUsed())
	} else {
		errorLog.Error().
			Err(err).
			Msgf("Unable to load configuration from file: %v", viper.ConfigFileUsed())
	}
	redirectHandler.SetRedirections(config.Redirections)
}

// Start the HTTP server
func Serve(cmd *cobra.Command, args []string) {
	errorLog.Info().
		Msgf("Listening on %s", addr)
	handler := accessLogHandler(accessLog, &redirectHandler)
	er(http.ListenAndServe(addr, handler))
}

// An HTTP handler that redirects requests
type RedirectHandler struct {
	mu     sync.Mutex
	redirs atomic.Value
}

// Handle a request
func (handler *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirs := handler.redirs.Load().(map[string]Redirection)
	if redirection, ok := redirs[r.Host]; ok {
		status := redirection.Status
		if status == 0 {
			status = http.StatusFound
		}
		http.Redirect(w, r, redirection.Target, status)
	} else {
		w.WriteHeader(http.StatusNotFound)
		if _, err := fmt.Fprint(w, "Not found\n"); err != nil {
			errorLog.Err(err).
				Send()
		}
	}
}

// Set the redirections
func (handler *RedirectHandler) SetRedirections(redirections []Redirection) {
	redirs := make(map[string]Redirection)
	for _, r := range redirections {
		if r.Host != "" {
			redirs[r.Host] = r
		}
		for _, h := range r.Hosts {
			redirs[h] = r
		}
	}

	handler.mu.Lock()
	handler.redirs.Store(redirs)
	handler.mu.Unlock()
}

// Log an HTTP handler with an access logger
func accessLogHandler(l zerolog.Logger, h http.Handler) http.Handler {
	c := alice.New()
	c = c.Append(hlog.NewHandler(l))
	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Log().
			Str("method", r.Method).
			Str("path", r.URL.String()).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Str("host", r.Host).
			Send()
	}))
	c = c.Append(hlog.RemoteAddrHandler("ip"))
	c = c.Append(hlog.UserAgentHandler("user_agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(ResponseHeaderHandler("target", "Location"))
	return c.Then(h)
}

// ResponseHeaderHandler adds given header from response's header as a field to
// the context's logger using fieldKey as field key.
func ResponseHeaderHandler(fieldKey string, headerKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if value := w.Header().Get(headerKey); value != "" {
				l := zerolog.Ctx(r.Context())
				l.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, value)
				})
			}
		})
	}
}
