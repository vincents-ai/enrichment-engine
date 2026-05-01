package behavioral_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/vincents-ai/enrichment-engine/test/behavioral/steps"
)

func TestFeatures(t *testing.T) {
	if os.Getenv("GODOG") != "1" {
		t.Skip("skipping godog tests; set GODOG=1 to run")
	}
	suite := godog.TestSuite{
		ScenarioInitializer: steps.InitializeScenario,
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{"features"},
		},
	}
	if status := suite.Run(); status != 0 {
		t.Fatal()
	}
}
