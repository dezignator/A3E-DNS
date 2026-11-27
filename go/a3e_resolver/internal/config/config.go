// Package config loads the resolver's configuration from a YAML file.
//
// We kept the config schema flat and explicit rather than nesting it
// under a generic map[string]interface{} because a flat schema fails
// loudly when a field is missing, and the resolver's configuration is
// security-sensitive enough that silent defaults are unacceptable.
package config

import (
    "fmt"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

// Config is the top-level resolver configuration.
type Config struct {
    Server    ServerConfig    `yaml:"server"`
    Pipeline  PipelineConfig  `yaml:"pipeline"`
    Metrics   MetricsConfig   `yaml:"metrics"`
    Logging   LoggingConfig   `yaml:"logging"`
}

// ServerConfig configures the resolver's own listener.
type ServerConfig struct {
    ListenAddress    string        `yaml:"listen_address"`
    ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`
    MaxConcurrent    int           `yaml:"max_concurrent"`
    ReadTimeout      time.Duration `yaml:"read_timeout"`
    WriteTimeout     time.Duration `yaml:"write_timeout"`
    IdleTimeout      time.Duration `yaml:"idle_timeout"`
}

// PipelineConfig configures the connection to the Python pipeline.
type PipelineConfig struct {
    Endpoint            string        `yaml:"endpoint"`
    DialTimeout         time.Duration `yaml:"dial_timeout"`
    RequestTimeout      time.Duration `yaml:"request_timeout"`
    MaxRetries          int           `yaml:"max_retries"`
    RetryBackoffBase    time.Duration `yaml:"retry_backoff_base"`
    RetryBackoffMax     time.Duration `yaml:"retry_backoff_max"`
    BatchSize           int           `yaml:"batch_size"`
    BatchFlushInterval  time.Duration `yaml:"batch_flush_interval"`
    EnableAttestation   bool          `yaml:"enable_attestation"`
    EnableAEE           bool          `yaml:"enable_aee"`
    InsecureSkipVerify  bool          `yaml:"insecure_skip_verify"`
    TLSCertPath         string        `yaml:"tls_cert_path"`
    TLSKeyPath          string        `yaml:"tls_key_path"`
    TLSCAPath           string        `yaml:"tls_ca_path"`
}

// MetricsConfig configures the Prometheus exporter.
type MetricsConfig struct {
    ListenAddress    string        `yaml:"listen_address"`
    Path             string        `yaml:"path"`
    Namespace        string        `yaml:"namespace"`
    Subsystem        string        `yaml:"subsystem"`
    UpdateInterval   time.Duration `yaml:"update_interval"`
}

// LoggingConfig configures the structured logger.
type LoggingConfig struct {
    Level  string `yaml:"level"`
    Format string `yaml:"format"`
}

// Load reads and validates a configuration file.
//
// We validated after unmarshalling rather than during, because the
// yaml package reports parse errors with line numbers but not
// semantic errors, and semantic errors (missing endpoint, invalid
// timeout) are what the operator actually needs to fix.
func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read config %q: %w", path, err)
    }
    var c Config
    if err := yaml.Unmarshal(data, &c); err != nil {
        return nil, fmt.Errorf("parse config %q: %w", path, err)
    }
    applyDefaults(&c)
    if err := c.Validate(); err != nil {
        return nil, fmt.Errorf("validate config: %w", err)
    }
    return &c, nil
}

// applyDefaults fills in sensible defaults for fields the operator did
// not set. The defaults are the values the reference deployment used
// in the thesis's E5/E6 experiments.
func applyDefaults(c *Config) {
    if c.Server.ListenAddress == "" {
        c.Server.ListenAddress = "0.0.0.0:8053"
    }
    if c.Server.ShutdownTimeout == 0 {
        c.Server.ShutdownTimeout = 15 * time.Second
    }
    if c.Server.MaxConcurrent == 0 {
        c.Server.MaxConcurrent = 1024
    }
    if c.Server.ReadTimeout == 0 {
        c.Server.ReadTimeout = 5 * time.Second
    }
    if c.Server.WriteTimeout == 0 {
        c.Server.WriteTimeout = 5 * time.Second
    }
    if c.Server.IdleTimeout == 0 {
        c.Server.IdleTimeout = 60 * time.Second
    }
    if c.Pipeline.DialTimeout == 0 {
        c.Pipeline.DialTimeout = 5 * time.Second
    }
    if c.Pipeline.RequestTimeout == 0 {
        c.Pipeline.RequestTimeout = 100 * time.Millisecond
    }
    if c.Pipeline.MaxRetries == 0 {
        c.Pipeline.MaxRetries = 2
    }
    if c.Pipeline.RetryBackoffBase == 0 {
        c.Pipeline.RetryBackoffBase = 10 * time.Millisecond
    }
    if c.Pipeline.RetryBackoffMax == 0 {
        c.Pipeline.RetryBackoffMax = 200 * time.Millisecond
    }
    if c.Pipeline.BatchSize == 0 {
        c.Pipeline.BatchSize = 32
    }
    if c.Pipeline.BatchFlushInterval == 0 {
        c.Pipeline.BatchFlushInterval = 5 * time.Millisecond
    }
    if c.Metrics.ListenAddress == "" {
        c.Metrics.ListenAddress = "0.0.0.0:9090"
    }
    if c.Metrics.Path == "" {
        c.Metrics.Path = "/metrics"
    }
    if c.Metrics.Namespace == "" {
        c.Metrics.Namespace = "a3e"
    }
    if c.Metrics.Subsystem == "" {
        c.Metrics.Subsystem = "resolver"
    }
    if c.Metrics.UpdateInterval == 0 {
        c.Metrics.UpdateInterval = 5 * time.Second
    }
    if c.Logging.Level == "" {
        c.Logging.Level = "info"
    }
    if c.Logging.Format == "" {
        c.Logging.Format = "json"
    }
}

// Validate rejects configurations the resolver cannot operate with.
func (c *Config) Validate() error {
    if c.Pipeline.Endpoint == "" {
        return fmt.Errorf("pipeline.endpoint is required")
    }
    if c.Pipeline.RequestTimeout <= 0 {
        return fmt.Errorf("pipeline.request_timeout must be positive")
    }
    if c.Pipeline.BatchSize <= 0 {
        return fmt.Errorf("pipeline.batch_size must be positive")
    }
    if c.Pipeline.MaxRetries < 0 {
        return fmt.Errorf("pipeline.max_retries must be non-negative")
    }
    if c.Server.MaxConcurrent <= 0 {
        return fmt.Errorf("server.max_concurrent must be positive")
    }
    return nil
}
