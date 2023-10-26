package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/docker/verify-docker-cli-plugin/internal/http"
)

const (
	SPDXPredicateType       = "https://spdx.dev/Document"
	ProvenancePredicateType = "https://slsa.dev/provenance/v0.2"
)

type IntotoStatement struct {
	intoto.StatementHeader
	Predicate json.RawMessage `json:"predicate"`
}

type ProvenanceDocument struct {
	BuildConfig struct {
		DigestMapping map[string]string `json:"digestMapping"`
		LLBDefinition []struct {
			ID string `json:"id"`
			OP struct {
				OP struct {
					Source struct {
						Identifier string `json:"identifier"`
					} `json:"source"`
				} `json:"Op"`
				Platform struct {
					OS           string `json:"OS"`
					Architecture string `json:"Architecture"`
					Variant      string `json:"Variant"`
				}
			} `json:"op"`
		} `json:"llbDefinition"`
	} `json:"buildConfig"`
	Metadata struct {
		Buildkit struct {
			VCS struct {
				Revision string `json:"revision"`
				Source   string `json:"source"`
			} `json:"vcs"`
			Source struct {
				Locations map[string]struct {
					Locations []struct {
						Ranges []struct {
							Start struct {
								Line int `json:"line"`
							} `json:"start"`
							End struct {
								Line int `json:"line"`
							} `json:"end"`
						} `json:"ranges"`
					} `json:"locations"`
				} `json:"locations"`
				Infos []struct {
					Path string `json:"filename"`
					Data string `json:"data"`
				} `json:"infos"`
			} `json:"source"`
			Layers map[string][][]struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			} `json:"layers"`
		} `json:"https://mobyproject.org/buildkit@v1#metadata"`
	} `json:"metadata"`
}

type AttestationManifest struct {
	Img            v1.Image
	Manifest       *v1.Manifest
	AttestationImg *remote.Descriptor
	Name           string
	Digest         string
}

func FetchAttestationManifest(ctx context.Context, image, platformStr string) (*AttestationManifest, error) {
	platform, err := parsePlatform(platformStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse platform %s: %w", platform, err)
	}

	// we want to get to the image index, so ignoring platform for now
	options := withOptions(ctx, nil)
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}
	desc, err := remote.Index(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain index manifest: %w", err)
	}
	ix, err := desc.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain index manifest: %w", err)
	}
	digest, err := imageDigestForPlatform(ix, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain image for platform: %w", err)
	}
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), digest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}
	i, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}
	img, _ := i.Image()

	attestationDigest, err := attestationDigestForDigest(ix, digest, "attestation-manifest")
	if err != nil {
		return nil, fmt.Errorf("failed to obtain attestation for image: %w", err)
	}
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), attestationDigest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}
	attestationImg, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}
	manifest := new(v1.Manifest)
	err = json.Unmarshal(attestationImg.Manifest, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %w", err)
	}

	attest := &AttestationManifest{
		Name:           image,
		Img:            img,
		Manifest:       manifest,
		AttestationImg: attestationImg,
		Digest:         digest,
	}
	return attest, nil
}

func withOptions(ctx context.Context, platform *v1.Platform) []remote.Option {
	// prepare options
	options := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithTransport(http.Transport()), remote.WithContext(ctx)}

	// add in platform into remote Get operation; this might conflict with an explicit digest, but we are trying anyway
	if platform != nil {
		options = append(options, remote.WithPlatform(*platform))
	}
	return options
}

func RawSignedAttestations(ia *AttestationManifest) ([]string, error) {
	manifest, ai := ia.Manifest, ia.AttestationImg

	var rawEnvs []string

	im, err := ai.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to convert descriptor to an image: %w", err)
	}
	ls, err := im.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}

	for i, l := range manifest.Layers {
		if strings.HasPrefix(string(l.MediaType), "application/vnd.in-toto.") && strings.HasSuffix(string(l.MediaType), "+dsse") {
			reader, err := ls[i].Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer reader.Close()
			content, err := io.ReadAll(reader)
			if err != nil {
				return nil, fmt.Errorf("failed to read contents: %w", err)
			}

			rawEnvs = append(rawEnvs, string(content))
		}
	}

	return rawEnvs, nil
}

func SignedAttestations(ia *AttestationManifest) ([]dsse.Envelope, error) {
	manifest, ai := ia.Manifest, ia.AttestationImg

	envs := make([]dsse.Envelope, 0)

	im, err := ai.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to convert descriptor to an image: %w", err)
	}
	ls, err := im.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}

	for i, l := range manifest.Layers {
		if strings.HasPrefix(string(l.MediaType), "application/vnd.in-toto.") && strings.HasSuffix(string(l.MediaType), "+dsse") {
			reader, err := ls[i].Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer reader.Close()
			content, err := io.ReadAll(reader)
			if err != nil {
				return nil, fmt.Errorf("failed to read contents: %w", err)
			}

			var env dsse.Envelope
			err = json.Unmarshal(content, &env)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal in-toto envelope: %w", err)
			}
			if env.PayloadType != "application/vnd.in-toto+json" {
				return nil, fmt.Errorf("invalid payload type %s", env.PayloadType)
			}
			envs = append(envs, env)
		}
	}

	return envs, nil
}

func imageDigestForPlatform(ix *v1.IndexManifest, platform *v1.Platform) (string, error) {
	for _, m := range ix.Manifests {
		if m.MediaType == ocispec.MediaTypeImageManifest && m.Platform.Equals(*platform) {
			return m.Digest.String(), nil
		}
	}
	return "", errors.New(fmt.Sprintf("no image found for platform %v", platform))
}

func attestationDigestForDigest(ix *v1.IndexManifest, imageDigest string, attestType string) (string, error) {
	for _, m := range ix.Manifests {
		if v, ok := m.Annotations["vnd.docker.reference.type"]; ok && v == attestType {
			if d, ok := m.Annotations["vnd.docker.reference.digest"]; ok && d == imageDigest {
				return m.Digest.String(), nil
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no attestation found for image %s", imageDigest))
}

// parsePlatform parses the provided platform string or attempts to obtain
// the platform of the current host system
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
