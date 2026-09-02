package com.example.sbomenricher.web;

import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Accepts a CycloneDX {@code bom.json} document and returns each component annotated with
 * known vulnerabilities from the public OSV.dev database.
 */
@RestController
public class EnrichController {

  private final EnrichmentService enrichmentService;

  public EnrichController(EnrichmentService enrichmentService) {
    this.enrichmentService = enrichmentService;
  }

  @PostMapping(path = "/enrich", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public List<EnrichedComponent> enrich(@RequestBody String bomJson) {
    return enrichmentService.enrich(bomJson);
  }
}
