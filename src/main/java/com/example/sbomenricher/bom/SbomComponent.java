package com.example.sbomenricher.bom;

/** One CycloneDX SBOM component we care about for vulnerability lookup. */
public record SbomComponent(String name, String version, String purl) {
}
