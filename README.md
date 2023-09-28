# docker verify CLI plugin

[![asciicast example](https://asciinema.org/a/VSbKetTOIUL0jhdISo2xICA6j.svg)](https://asciinema.org/a/VSbKetTOIUL0jhdISo2xICA6j)

A docker CLI plugin for verifying signed attestations on images.

This plugin uses the OpenPubkey [signed-attestations](https://github.com/openpubkey/signed-attestation)
library to verify OpenPubkey tokens inside signed in-toto attestations.

## Installation

To build with Go and install as a docker CLI plugin:

```
$ go build -o ~/.docker/cli-plugins/docker-verify cmd/docker-verify/main.go
```

## Usage

```
$ docker verify IMAGE --repo-owner-id OWNER_ID
```

`OWNER_ID` is the Github ID of the organization or user that owns the source repository. This must match
the owner in the OIDC ID token from the GitHub Actions run.

### Example

```
$ docker verify openpubkey/demo:main --repo-owner-id 145685596
```
