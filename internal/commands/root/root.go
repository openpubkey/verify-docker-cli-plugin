package root

import (
	"fmt"

	"github.com/docker/verify-docker-cli-plugin/internal/attestation"
	"github.com/docker/verify-docker-cli-plugin/internal/commands"
	"github.com/docker/verify-docker-cli-plugin/verify"
	signedattestation "github.com/openpubkey/signed-attestation"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/docker/cli/cli/command"
	"github.com/docker/verify-docker-cli-plugin/internal"
)

func NewCmd(dockerCli command.Cli, isPlugin bool) *cobra.Command {
	var platform, repoOwnerID string

	debug := false
	name := internal.SubCommandName
	if !isPlugin {
		name = internal.BinaryName
	}
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s IMAGE", name),
		Short: "Command line tool for verifying signed attestations on docker images",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				image = commands.FirstArg(args)
				ctx   = cmd.Context()
			)
			attest, err := attestation.FetchAttestationManifest(ctx, image, platform)
			if err != nil {
				return err
			}

			envs, err := attestation.SignedAttestations(attest, image, platform)
			if err != nil {
				return err
			}

			err = verify.VerifyInTotoEnvelopes(ctx, image, attest.Digest, platform, repoOwnerID, envs, signedattestation.GithubActionsOIDC)
			if err != nil {
				return err
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&platform, "platform", "", "platform")
	f.StringVar(&repoOwnerID, "repo-owner-id", "", "owner ID of the repo")
	cmd.MarkFlagRequired("repo-owner-id")

	if isPlugin {
		originalPreRun := cmd.PersistentPreRunE
		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			if err := plugin.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
			if originalPreRun != nil {
				if err := originalPreRun(cmd, args); err != nil {
					return err
				}
			}
			return nil
		}
	} else {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.TraverseChildren = true
		cmd.DisableFlagsInUseLine = true
		cli.DisableFlagsInUseLine(cmd)
	}

	addDebugFlag(cmd.PersistentFlags(), &debug)

	return cmd
}

func addDebugFlag(f *pflag.FlagSet, debug *bool) {
	f.BoolVar(debug, "debug", false, "Debug messages")
	_ = f.MarkHidden("debug") // Ignoring the error, the flag is defined on the above line
}
