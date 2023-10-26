package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/containerd/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/verify-docker-cli-plugin/internal/render"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	signedattestation "github.com/openpubkey/signed-attestation"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"
)

func VerifyWithPolicy(ctx context.Context, ref, fullDigest, platform, policy string, envs []string) error {
	purl, isCanonical, err := refToPURL("docker", ref, platform)
	if err != nil {
		return err
	}

	r := rego.New(
		rego.Load([]string{policy}, nil),
		rego.Query(`data.doi.allow`),
		// rego.EnablePrintStatements(true),
		rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		rego.StrictBuiltinErrors(true),
		rego.Input(map[string]any{"envelopes": envs, "fullDigest": fullDigest, "purl": purl, "canonical": isCanonical}),
		rego.Function2(
			&rego.Function{
				Name:             "openpubkey.verify_intoto_envelope",
				Decl:             types.NewFunction(types.Args(types.S, types.S), types.NewArray([]types.Type{types.A, types.A}, nil)),
				Memoize:          true,
				Nondeterministic: true,
			},
			func(rCtx rego.BuiltinContext, envTerm, providerTerm *ast.Term) (*ast.Term, error) {
				envAst := envTerm.Value.(ast.String)
				providerAst := providerTerm.Value.(ast.String)

				envBytes := []byte(envAst)
				provider := string(providerAst)

				var env dsse.Envelope
				err := json.Unmarshal(envBytes, &env)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal in-toto envelope: %w", err)
				}
				if env.PayloadType != "application/vnd.in-toto+json" {
					return nil, fmt.Errorf("invalid payload type %s", env.PayloadType)
				}

				statement, err := signedattestation.VerifyInTotoEnvelope(rCtx.Context, env, signedattestation.OIDCProvider(provider))
				if err != nil {
					return nil, err
				}

				opkJWSJSON, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
				if err != nil {
					return nil, err
				}

				opkJWS := new(struct{ Payload string })
				err = json.Unmarshal(opkJWSJSON, opkJWS)
				if err != nil {
					return nil, err
				}

				payloadJSON, err := base64.RawURLEncoding.DecodeString(opkJWS.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to base64 decode payload: %w", err)
				}
				var payload map[string]any
				err = json.Unmarshal(payloadJSON, &payload)
				if err != nil {
					return nil, fmt.Errorf("failed to json unmarshal payload: %w", err)
				}

				result := []any{statement, payload}

				value, err := ast.InterfaceToValue(result)
				if err != nil {
					return nil, err
				}

				return ast.NewTerm(value), nil
			}),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return fmt.Errorf("error from Eval: %w", err)
	}

	if !rs.Allowed() {
		return fmt.Errorf("policy evaluation failed")
	}

	renderer := render.NewRenderer()
	renderer.Success("Verified successfully")

	return nil
}

func findSubject(stmt *intoto.Statement, fullDigest string) (*intoto.Subject, error) {
	digestType, digest, found := strings.Cut(fullDigest, ":")
	if !found {
		return nil, fmt.Errorf("expected fullDigest to contain ':', got %q", fullDigest)
	}

	for _, sub := range stmt.Subject {
		subDigest, found := sub.Digest[digestType]
		if !found {
			continue
		}

		if subDigest != digest {
			continue
		}

		return &sub, nil
	}

	return nil, nil
}

func refToPURL(purlType string, ref string, platform string) (string, bool, error) {
	var isCanonical bool
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse ref %q: %w", ref, err)
	}
	var qualifiers []packageurl.Qualifier

	if canonical, ok := named.(reference.Canonical); ok {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "digest",
			Value: canonical.Digest().String(),
		})
		isCanonical = true
	} else {
		named = reference.TagNameOnly(named)
	}

	version := ""
	if tagged, ok := named.(reference.Tagged); ok {
		version = tagged.Tag()
	}

	name := reference.FamiliarName(named)

	ns := ""
	parts := strings.Split(name, "/")
	if len(parts) > 1 {
		ns = strings.Join(parts[:len(parts)-1], "/")
	}
	name = parts[len(parts)-1]

	pf, err := parsePlatform(platform)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse platform %q: %w", platform, err)
	}
	if pf != nil {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "platform",
			Value: pf.String(),
		})
	}

	p := packageurl.NewPackageURL(purlType, ns, name, version, qualifiers, "")
	return p.ToString(), isCanonical, nil
}

func parsePlatform(platformStr string) (*v1.Platform, error) {
	if platformStr == "" {
		cdp := platforms.Normalize(platforms.DefaultSpec())
		if cdp.OS != "windows" {
			cdp.OS = "linux"
		}
		return &v1.Platform{
			OS:           cdp.OS,
			Architecture: cdp.Architecture,
			Variant:      cdp.Variant,
		}, nil
	} else {
		return v1.ParsePlatform(platformStr)
	}
}
