package com.example.sbomenricher.osv;

import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Thin client for the public OSV.dev vulnerability database (https://osv.dev/). */
@Component
public class OsvClient {

  private final RestClient restClient;

  public OsvClient(RestClient.Builder restClientBuilder) {
    this.restClient = restClientBuilder
        .baseUrl("https://api.osv.dev")
        .build();
  }

  /** Looks up known vulnerabilities for a single package by purl. Never returns null. */
  public List<OsvVulnerability> queryByPurl(String purl) {
    OsvQueryResponse response = restClient.post()
        .uri("/v1/query")
        .body(new OsvQueryRequest(new OsvPackage(purl)))
        .retrieve()
        .body(OsvQueryResponse.class);

    return response == null ? List.of() : response.vulnsOrEmpty();
  }
}
