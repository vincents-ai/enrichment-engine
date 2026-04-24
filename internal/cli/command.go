// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// Command defines the interface for CLI commands.
// This allows for better testing and dependency injection.
type Command interface {
	// Name returns the command name
	Name() string

	// Description returns the short description
	Description() string

	// Execute runs the command with the given context and arguments
	Execute(ctx context.Context, args []string) error

	// CobraCommand returns the underlying cobra.Command for registration
	CobraCommand() *cobra.Command
}

// BaseCommand provides common functionality for CLI commands
type BaseCommand struct {
	name        string
	description string
}

// Name returns the command name
func (c *BaseCommand) Name() string {
	return c.name
}

// Description returns the command description
func (c *BaseCommand) Description() string {
	return c.description
}

// RunCommand implements Command for running the enrichment pipeline
type RunCommand struct {
	BaseCommand
	all            bool
	providers      []string
	skipMapping    bool
	maxParallel    int
	enableTagMapping bool
	vulnzWorkspace string
}

// NewRunCommand creates a new RunCommand
func NewRunCommand() *RunCommand {
	return &RunCommand{
		BaseCommand: BaseCommand{
			name:        "run",
			description: "Run GRC providers and enrichment pipeline",
		},
	}
}

// Execute runs the run command
func (c *RunCommand) Execute(ctx context.Context, args []string) error {
	// Delegates to existing runCmd logic
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *RunCommand) CobraCommand() *cobra.Command {
	return runCmd()
}

// IngestCommand implements Command for ingesting vulnerability data
type IngestCommand struct {
	BaseCommand
}

// NewIngestCommand creates a new IngestCommand
func NewIngestCommand() *IngestCommand {
	return &IngestCommand{
		BaseCommand: BaseCommand{
			name:        "ingest",
			description: "Ingest vulnerability data into the workspace",
		},
	}
}

// Execute runs the ingest command
func (c *IngestCommand) Execute(ctx context.Context, args []string) error {
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *IngestCommand) CobraCommand() *cobra.Command {
	return ingestCmd()
}

// ExportCommand implements Command for exporting data
type ExportCommand struct {
	BaseCommand
}

// NewExportCommand creates a new ExportCommand
func NewExportCommand() *ExportCommand {
	return &ExportCommand{
		BaseCommand: BaseCommand{
			name:        "export",
			description: "Export GRC controls and mappings",
		},
	}
}

// Execute runs the export command
func (c *ExportCommand) Execute(ctx context.Context, args []string) error {
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *ExportCommand) CobraCommand() *cobra.Command {
	return exportCmd()
}

// Commands returns a list of all CLI commands
func Commands() []Command {
	return []Command{
		NewRunCommand(),
		NewIngestCommand(),
		NewExportCommand(),
	}
}
