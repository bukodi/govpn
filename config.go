package govpn

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

var cfg map[string]any

func LoadConfig() error {
	// A default value for the config path
	if configfile := os.Getenv("GOVPN_CONFIG_FILE"); configfile == "" {
		return fmt.Errorf("missing env variable: \"GOVPN_CONFIG_FILE\"")
	} else if data, err := os.ReadFile(configfile); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config file: %w", err)
	} else {
		slog.Info("config loaded from: %s", configfile)
		return nil
	}
}

func ConfigString(key string) string {
	parts := strings.Split(key, "/")

	for i, root := 0, cfg; i < len(parts); i++ {
		if i == len(parts)-1 {
			return root[parts[i]].(string)
		} else {
			root = root[parts[i]].(map[string]any)
		}
	}
	panic("entry not found")
}
