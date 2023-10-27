package doi

import future.keywords

splitDigest := split(input.fullDigest, ":")

digestType := splitDigest[0]

digest := splitDigest[1]

allow if {
	every env in input.envelopes {
		[statement, _] := openpubkey.verify_intoto_envelope(env, "gha")

		valid_subject(statement.subject[_])
	}

	some prov in input.envelopes
	valid_provenance(prov)

	some sbom in input.envelopes
	valid_sbom(sbom)
}

valid_subject(subject) if {
	subject.digest[digestType] == digest
	valid_subject_name(subject.name)
}

valid_subject_name(name) if {
	input.canonical
}

valid_subject_name(name) if {
	# TODO: urlquery.decode required because buildkit uses an old version of
	# anchore/package-url which incorrectly url escapes '/' characters in the
	# platform qualifier
	urlquery.decode(name) == input.purl
	print("verified subject matches", input.purl)
}

valid_provenance(env) if {
	[statement, oidc] := openpubkey.verify_intoto_envelope(env, "gha")

	statement.predicateType == "https://slsa.dev/provenance/v0.2"
	statement.predicate.buildType == "https://mobyproject.org/buildkit@v1"

	oidc.repository == "openpubkey/demo"
	repository := sprintf("https://github.com/%s", [oidc.repository])

	buildkit := statement.predicate.metadata["https://mobyproject.org/buildkit@v1#metadata"]
	buildkit.vcs.source == repository
	buildkit.vcs.revision == oidc.sha

	actionRunURL := sprintf("https://github.com/%s/actions/runs/%s", [oidc.repository, oidc.run_id])
	statement.predicate.builder.id == actionRunURL
	print("verified build from", actionRunURL)
}

valid_sbom(env) if {
	[statement, _] := openpubkey.verify_intoto_envelope(env, "gha")

	statement.predicateType == "https://spdx.dev/Document"
}
