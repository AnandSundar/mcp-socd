package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
)

// DefaultConfigName is the file name mcp-socd looks for under the XDG
// config home when --config is not provided.
const DefaultConfigName = "config.yaml"

// DefaultConfigPath returns the XDG-resolved path to the user config file.
//
// Linux:   $XDG_CONFIG_HOME/mcp-socd/config.yaml (default ~/.config/mcp-socd/config.yaml)
// macOS:   ~/Library/Application Support/mcp-socd/config.yaml
// Windows: %LOCALAPPDATA%\mcp-socd\config.yaml
//
// Returns an empty string if no usable home directory is found.
func DefaultConfigPath() (string, error) {
	path, err := xdg.ConfigFile(DefaultConfigName)
	if err != nil {
		return "", fmt.Errorf("resolve xdg config path: %w", err)
	}
	return path, nil
}

// EnsureConfigDir creates the parent directory of path if it does not exist.
// Used by tools that write a starter config to disk.
func EnsureConfigDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o755)
}
