package verify

type Policy struct {
	Policy struct {
		Attestations []string
		Signature    struct {
			Iss               string
			RepositoryOwnerId string
		}
		Provenance string
		Tag        string
	}
}

func demoPolicy(repoOwnerID string) Policy {
	return Policy{
		Policy: struct {
			Attestations []string
			Signature    struct {
				Iss               string
				RepositoryOwnerId string
			}
			Provenance string
			Tag        string
		}{
			Attestations: []string{"https://slsa.dev/provenance/v0.2"},
			Signature: struct {
				Iss               string
				RepositoryOwnerId string
			}{
				Iss:               "https://token.actions.githubusercontent.com",
				RepositoryOwnerId: repoOwnerID,
			},
			Tag: "strict",
		},
	}
}
