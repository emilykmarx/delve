package conftamer

import (
	"fmt"
	"io"
	"os"

	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	// File to set initial breakpoint
	Initial_bp_file string `yaml:"initial_bp_file"`
	// Line number to set initial breakpoint
	Initial_bp_line int `yaml:"initial_bp_line"`
	// Expression to set initial watchpoint
	Initial_watchexpr string `yaml:"initial_watchexpr"`
	// Target module name
	Module string `yaml:"module"`
	// Whether to request move object on setting software watchpoint
	Move_wps bool `yaml:"move_wps"`
	// Filename for event log
	Event_log_filename string `yaml:"event_log_filename"`
	// Filename for final behavior map
	Behavior_map_filename string `yaml:"behavior_map_filename"`
	// Delve server endpoint
	Server_endpoint string `yaml:"server_endpoint"`
}

func LoadConfig(file string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return &Config{}, fmt.Errorf("opening config file: %v", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return &Config{}, fmt.Errorf("unable to read config data: %v", err)
	}

	var c Config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return &Config{}, fmt.Errorf("unable to decode config file: %v", err)
	}

	return &c, nil
}

func SaveConfig(file string, conf Config) error {
	out, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(out)
	return err
}
