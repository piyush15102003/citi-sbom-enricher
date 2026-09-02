package com.example.sbomenricher.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Response body from {@code POST https://api.osv.dev/v1/query}. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvQueryResponse(List<OsvVulnerability> vulns) {

  public List<OsvVulnerability> vulnsOrEmpty() {
    return vulns == null ? List.of() : vulns;
  }
}
