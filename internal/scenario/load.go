package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/szey/Aegis_Router/internal/models"
)

func LoadDirectory(path string) ([]models.Scenario, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario directory: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	scenarios := make([]models.Scenario, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			return nil, fmt.Errorf("read scenario %s: %w", name, err)
		}
		var item models.Scenario
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf("parse scenario %s: %w", name, err)
		}
		scenarios = append(scenarios, item)
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("no scenario files found in %s", path)
	}
	return scenarios, nil
}
