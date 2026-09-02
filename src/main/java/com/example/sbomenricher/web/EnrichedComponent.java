package com.example.sbomenricher.web;

import java.util.List;

/** One SBOM component annotated with the vulnerabilities OSV.dev knows about for it. */
public record EnrichedComponent(
    String name,
    String version,
    String purl,
    List<VulnerabilitySummary> vulnerabilities) {

  public record VulnerabilitySummary(String id, String summary, String severity) {
  }
}
