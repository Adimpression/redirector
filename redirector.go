package main

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/justinas/alice"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//
// Command line handling
//

const (
	name             = "redirector"           // Program name
	cfgFileDefault   = "/etc/redirector.yaml" // Default configuration file path
	addrDefault      = "127.0.0.1:8000"       // Default address and port to addr on
	logLevelDefault  = "info"                 // Default log level
	logFormatDefault = "color"                // Default log format
)

var (
	version   = "development" // Project version, set by GoReleaser
	cfgFile   string          // Configuration file path
	addr      string          // Address and port to listen on
	logLevel  string          // Log level
	logFormat string          // Log format
)

// The root command defines the command line interface
var rootCmd = &cobra.Command{
	Use:     name,
	Short:   "HTTP server that redirects requests.",
	Version: version,
	Run:     Serve,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", cfgFileDefault, "config file")
	rootCmd.Flags().StringVarP(&addr, "listen", "l", addrDefault, "the address and port to listen on")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "L", logLevelDefault, "the log level: trace/debug/info/warn/error/fatal/panic")
	rootCmd.Flags().StringVarP(&logFormat, "log-format", "F", logFormatDefault, "the log format: color/nocolor/json")
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
	_, _ = fmt.Fprintf(os.Stderr, "%v: %v\n", name, msg)
	os.Exit(1)
}

// Print a formatted error message on stderr and exit with a non-zero code
func erf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	er(msg)
}

//
// Configuration
//

var (
	accessLog zerolog.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	errorLog  zerolog.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
)

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
		if err := loadConfiguration(); err != nil {
			errorLog.Error().
				Err(err).
				Msg("Error reloading configuration")
		}
	})
	if err := loadConfiguration(); err != nil {
		errorLog.Fatal().
			Err(err).
			Msg("Error loading configuration")
	}
}

// The configuration
type Config struct {
	Redirections []Redirection `yaml:"redirections"`
}

// A redirection specification
type Redirection struct {
	Host      string
	Hosts     []string
	PathReStr string `mapstructure:"path_re"`
	Target    string
	Status    int

	pathRe regexp.Regexp
}

//
// HTTP server

// Start the HTTP server
func Serve(cmd *cobra.Command, args []string) {
	errorLog.Info().
		Msgf("Listening on %s", addr)
	handler := accessLogHandler(accessLog, &redirectHandler)
	er(http.ListenAndServe(addr, handler))
}

// Called when the configuration is (re)loaded
func loadConfiguration() error {
	var config Config

	// Parse configuration
	if err := viper.UnmarshalExact(&config); err == nil {
		errorLog.Info().
			Msgf("Configuration loaded from file: %v", viper.ConfigFileUsed())
	} else {
		return errors.Wrapf(err, "Unable to load configuration from file: %v", viper.ConfigFileUsed())
	}

	// Post processing
	for i, _ := range config.Redirections {
		r := &config.Redirections[i]

		// Collect all hosts
		if r.Hosts == nil {
			r.Hosts = []string{}
		}
		if r.Host != "" {
			r.Hosts = append([]string{r.Host}, r.Hosts...)
		}

		// Verify that at least one host is set
		if len(r.Hosts) == 0 {
			return errors.New("All redirections must have hosts")
		}

		// Verify exactly target is set
		if r.Target == "" {
			return errors.Errorf("Target must be set: %s", strings.Join(r.Hosts, ", "))
		}

		// Compile the path regex
		if r.PathReStr != "" {
			if re, err := regexp.Compile(r.PathReStr); err == nil {
				r.pathRe = *re
			} else {
				return errors.Wrapf(err, "Unable to parse regex: \"%s\"", re)
			}
		}
	}

	redirectHandler.SetRedirections(config.Redirections)
	return nil
}

//
// Redirection
//

// The redirection handler instance
var redirectHandler = RedirectHandler{}

// An HTTP handler that redirects requests
type RedirectHandler struct {
	mu     sync.Mutex
	redirs atomic.Value
}

// Handle a request
func (handler *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirs := handler.redirs.Load().(map[string]Redirection)
	if redir, ok := redirs[r.Host]; ok {
		status := redir.Status
		if status == 0 {
			status = http.StatusFound
		}
		var target string
		if redir.PathReStr != "" {
			target = redir.pathRe.ReplaceAllString(r.RequestURI, redir.Target)
		} else {
			target = redir.Target
		}
		http.Redirect(w, r, target, status)
	} else {
		w.WriteHeader(http.StatusNotFound)
		if _, err := fmt.Fprint(w, "Not found.\n"); err != nil {
			errorLog.Err(err).
				Send()
		}
	}
}

// Set the redirections
func (handler *RedirectHandler) SetRedirections(redirections []Redirection) {
	redirs := make(map[string]Redirection)
	for _, r := range redirections {
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
