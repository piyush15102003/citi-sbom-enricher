package com.example.sbomenricher.bom;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Extracts the components worth checking for known vulnerabilities out of a CycloneDX
 * {@code bom.json} document (the format produced by Citi's own forked
 * {@code cyclonedx-maven-plugin}/{@code cyclonedx-gradle-plugin}).
 *
 * <p>Only the {@code components[].purl} field is required by OSV.dev's query API, but
 * {@code name}/{@code version} are kept for a readable report even when a component has no purl
 * (in which case it is skipped, since OSV has nothing to match against).
 */
@Component
public class BomParser {

  private final ObjectMapper objectMapper;

  public BomParser(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  public List<SbomComponent> parse(String bomJson) {
    List<SbomComponent> components = new ArrayList<>();
    JsonNode root;
    try {
      root = objectMapper.readTree(bomJson);
    } catch (Exception e) {
      throw new IllegalArgumentException("bom.json is not valid JSON", e);
    }

    JsonNode componentsNode = root.path("components");
    if (!componentsNode.isArray()) {
      return components;
    }

    for (JsonNode c : componentsNode) {
      String purl = c.path("purl").asText(null);
      if (purl == null || purl.isBlank()) {
        continue;
      }
      String name = c.path("name").asText(null);
      String version = c.path("version").asText(null);
      components.add(new SbomComponent(name, version, purl));
    }
    return components;
  }
}
