package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/docker/cli/cli"
)

func CliError(err error) error {
	return cli.StatusError{
		StatusCode: 1,
		Status:     err.Error(),
	}
}

func CliErrorMessage(msg string) error {
	return cli.StatusError{
		StatusCode: 1,
		Status:     msg,
	}
}

func CliErrorf(format string, a ...any) error {
	return cli.StatusError{
		StatusCode: 1,
		Status:     fmt.Errorf(format, a...).Error(),
	}
}

func ExactArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			_ = cmd.Help()
			return CliErrorMessage(fmt.Sprintf("accepts 1 argument, received %d", len(args)))
		}
		return nil
	}
}

func MaxArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > n {
			_ = cmd.Help()
			return CliErrorMessage(fmt.Sprintf("accepts max %d argument, received %d", n, len(args)))
		}
		return nil
	}
}

func FirstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}
