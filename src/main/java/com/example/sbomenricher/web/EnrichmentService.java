package com.example.sbomenricher.web;

import com.example.sbomenricher.bom.BomParser;
import com.example.sbomenricher.bom.SbomComponent;
import com.example.sbomenricher.osv.OsvClient;
import com.example.sbomenricher.osv.OsvVulnerability;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class EnrichmentService {

  private final BomParser bomParser;
  private final OsvClient osvClient;

  public EnrichmentService(BomParser bomParser, OsvClient osvClient) {
    this.bomParser = bomParser;
    this.osvClient = osvClient;
  }

  public List<EnrichedComponent> enrich(String bomJson) {
    List<SbomComponent> components = bomParser.parse(bomJson);
    return components.stream()
        .map(this::enrichOne)
        .toList();
  }

  private EnrichedComponent enrichOne(SbomComponent component) {
    List<OsvVulnerability> vulns = osvClient.queryByPurl(component.purl());
    List<EnrichedComponent.VulnerabilitySummary> summaries = vulns.stream()
        .map(v -> new EnrichedComponent.VulnerabilitySummary(
            v.id(),
            v.summary(),
            firstSeverityOrUnknown(v)))
        .toList();
    return new EnrichedComponent(component.name(), component.version(), component.purl(), summaries);
  }

  private String firstSeverityOrUnknown(OsvVulnerability vuln) {
    if (vuln.severity() == null || vuln.severity().isEmpty()) {
      return "UNKNOWN";
    }
    return vuln.severity().get(0).score();
  }
}
