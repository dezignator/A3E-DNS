// Command server is the A3E-DNS resolver entry point.
//
// The command's structure is deliberately thin: parse flags, load
// config, construct the server, run it. Everything testable lives in
// the internal packages; the entry point's only job is to assemble the
// pieces.
package main

import (
    "context"
    "flag"
    "fmt"
    "log/slog"
    "os"

    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/api"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/config"
)

var (
    configPath = flag.String("config", "/etc/a3e-resolver/config.yaml", "path to the configuration file")
    version    = flag.Bool("version", false, "print version and exit")
)

// buildVersion is set at compile time via -ldflags.
var buildVersion = "0.1.0-dev"

func main() {
    flag.Parse()

    if *version {
        fmt.Println("a3e-resolver", buildVersion)
        return
    }

    cfg, err := config.Load(*configPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "config error: %v\n", err)
        os.Exit(1)
    }

    logger := newLogger(cfg.Logging)
    slog.SetDefault(logger)

    server, err := api.New(cfg, logger)
    if err != nil {
        logger.Error("server construction failed", "error", err)
        os.Exit(1)
    }

    if err := server.Run(context.Background()); err != nil {
        logger.Error("server run failed", "error", err)
        os.Exit(1)
    }
}

// newLogger builds the structured logger from the config.
//
// We default to JSON output because the deployment pipeline's log
// aggregator expects JSON; the human-readable text handler is
// available for local development through the config's `format: text`
// override.
func newLogger(c config.LoggingConfig) *slog.Logger {
    var level slog.Level
    switch c.Level {
    case "debug":
        level = slog.LevelDebug
    case "info":
        level = slog.LevelInfo
    case "warn":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    default:
        level = slog.LevelInfo
    }
    opts := &slog.HandlerOptions{Level: level}

    if c.Format == "text" {
        return slog.New(slog.NewTextHandler(os.Stdout, opts))
    }
    return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
