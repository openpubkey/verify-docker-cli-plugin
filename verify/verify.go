package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/containerd/containerd/platforms"
	"github.com/docker/distribution/reference"
	"github.com/docker/verify-docker-cli-plugin/internal/attestation"
	"github.com/docker/verify-docker-cli-plugin/internal/render"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/mitchellh/mapstructure"
	signedattestation "github.com/openpubkey/signed-attestation"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyInTotoEnvelopes(ctx context.Context, ref, fullDigest, platform, repoOwnerID string, envs []dsse.Envelope, oidcProvider signedattestation.OIDCProvider) error {
	policy := demoPolicy(repoOwnerID)

	purl, err := refToPURL("docker", ref, platform)
	if err != nil {
		return err
	}

	renderer := render.NewRenderer()

	attestationTypes := make([]string, 0)
	renderer.Render("Verifying %v attestations for %v", len(envs), purl)

	for _, env := range envs {
		renderer.NewLine()

		stmt, err := signedattestation.VerifyInTotoEnvelope(ctx, env, oidcProvider)

		renderer.Render("Verifying %v attestation", stmt.PredicateType)
		subRender := renderer.AddNesting()

		// enforce statement type
		if stmt.StatementHeader.Type != intoto.StatementInTotoV01 {
			return fmt.Errorf("invalid in-toto statement type %s", stmt.StatementHeader.Type)
		}

		attestationTypes = append(attestationTypes, stmt.PredicateType)

		subject, err := findSubject(stmt, fullDigest)
		if err != nil {
			return err
		}

		if subject == nil {
			return fmt.Errorf("attestation does not refer to digest %s", fullDigest)
		}

		subRender.Success("Verified attestation refers to digest %s", fullDigest)

		if policy.Policy.Tag == "strict" {
			named, err := reference.ParseNormalizedNamed(ref)
			if err != nil {
				return fmt.Errorf("failed to parse ref %q: %w", ref, err)
			}

			switch named.(type) {
			case reference.Canonical:
				// canonical reference, ignoring strict tag checking...
			default:
				// TODO: required because buildkit uses an old version of anchore/package-url
				// which incorrectly url escapes '/' characters in the platform qualifier
				subPurl, err := url.QueryUnescape(subject.Name)
				if err != nil {
					return err
				}

				if subPurl != purl {
					return fmt.Errorf("attestation does not refer to tag %s", ref)
				}
				subRender.Success("Verified attestation refers to tag %s", ref)
			}
		}

		opkJWSJSON, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
		if err != nil {
			return err
		}

		opkJWS := new(struct{ Payload string })
		err = json.Unmarshal(opkJWSJSON, opkJWS)
		if err != nil {
			return err
		}

		payloadJSON, err := base64.RawURLEncoding.DecodeString(opkJWS.Payload)
		if err != nil {
			return fmt.Errorf("failed to base64 decode payload: %w", err)
		}
		var payload map[string]any
		err = json.Unmarshal(payloadJSON, &payload)
		if err != nil {
			return fmt.Errorf("failed to json unmarshal payload: %w", err)
		}

		subRender.Success("Verified OIDC token was signed by %v", payload["iss"])
		actionRunURL := fmt.Sprintf("https://github.com/%v/actions/runs/%v", payload["repository"], payload["run_id"])
		subRender.Success("Verified attestation digest was signed on a Github Actions run: %v", actionRunURL)

		// check repository owner
		if payload["repository_owner_id"] == policy.Policy.Signature.RepositoryOwnerId {
			subRender.Success("Verified repository owner %s (%s)", payload["repository_owner_id"], payload["repository_owner"])
		} else {
			return fmt.Errorf("failed to verify repository owner, expected %s, got %s (%s)", policy.Policy.Signature.RepositoryOwnerId, payload["repository_owner_id"], payload["repository_owner"])
		}

		// check provenance
		if stmt.PredicateType == attestation.ProvenancePredicateType {
			var prov attestation.ProvenanceDocument
			ms, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: &prov})
			if err != nil {
				panic(err)
			}
			err = ms.Decode(stmt.Predicate.(map[string]any))
			if err != nil {
				return errors.Wrap(err, "failed to unmarshal provenance document")
			}
			if prov.Metadata.Buildkit.VCS.Revision == payload["sha"] {
				subRender.Success("Verified signed git sha provenance %s", payload["sha"])
			} else {
				return fmt.Errorf("failed to verify signed git sha provenance, provenance = %q, oidc = %q", prov.Metadata.Buildkit.VCS.Revision, payload["sha"])
			}
			if prov.Metadata.Buildkit.VCS.Source == fmt.Sprintf("https://github.com/%s", payload["repository"]) {
				subRender.Success("Verified signed git repo provenance %s", payload["repository"])
			} else {
				return fmt.Errorf("failed to verify signed git repo provenance")
			}
		}
	}

	renderer.NewLine()

	// check that all configured attestations are present
	if len(policy.Policy.Attestations) > 0 {
		for _, attType := range policy.Policy.Attestations {
			typeFound := false
			for _, t := range attestationTypes {
				if t == attType {
					typeFound = true
				}
			}
			if !typeFound {
				return fmt.Errorf("missing required attestation %s", attType)
			}
		}
		renderer.Render("Verified all required attestations are present")
	}

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

func refToPURL(purlType string, ref string, platform string) (string, error) {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return "", fmt.Errorf("failed to parse ref %q: %w", ref, err)
	}
	var qualifiers []packageurl.Qualifier

	if canonical, ok := named.(reference.Canonical); ok {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "digest",
			Value: canonical.Digest().String(),
		})
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
		return "", fmt.Errorf("failed to parse platform %q: %w", platform, err)
	}
	if pf != nil {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "platform",
			Value: pf.String(),
		})
	}

	p := packageurl.NewPackageURL(purlType, ns, name, version, qualifiers, "")
	return p.ToString(), nil
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
