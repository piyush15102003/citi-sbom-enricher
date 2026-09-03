# SBOM Vulnerability Enricher

Small Spring Boot prototype that enriches a CycloneDX SBOM with live vulnerability data.
Grounded in Citi's forks and runs `cyclonedx-maven-plugin`/
`cyclonedx-gradle-plugin` (SBOM generation) and `dependency-track` (SCA/component-risk) internally
for build-compliance and dependency-risk auditing. No PR-able gap existed in an
actively-maintained Citi Java repo, so this is a standalone demonstration in that same domain
rather than a PR.

## What it does

`POST /enrich` accepts a CycloneDX `bom.json` document (the format Citi's own forked
`cyclonedx-maven-plugin` produces), looks up each component's [purl](https://github.com/package-url/purl-spec)
against the public [OSV.dev](https://osv.dev/) vulnerability database, and returns each component
annotated with the known CVEs/GHSAs and severity found for it.

## Design

- `bom` package - `BomParser` extracts `{name, version, purl}` for every component in the SBOM
  that has a purl (components without one are skipped, since OSV has nothing to match against).
- `osv` package - `OsvClient` is a thin wrapper over `POST https://api.osv.dev/v1/query`, built on
  Spring's `RestClient`.
- `web` package - `EnrichmentService` ties parsing and lookup together; `EnrichController` exposes
  the `/enrich` endpoint.

## Running it

```
./mvnw spring-boot:run
```

Then, in another terminal:

```
curl -X POST http://localhost:8080/enrich \
  -H "Content-Type: application/json" \
  --data-binary @src/main/resources/samples/bom.json
```

The bundled sample BOM includes a deliberately old `jackson-databind`/`spring-core` (both with
many real, known CVEs) and a current `guava` (clean), to make the enrichment visible.

## Tests

```
./mvnw test
```

Covers BOM parsing (including components missing a purl, and invalid JSON), the OSV client
(mocked HTTP via `MockRestServiceServer`), and the controller (`MockMvc`). Verified end-to-end
against the live OSV.dev API as well - see the commit message for the recorded result.
