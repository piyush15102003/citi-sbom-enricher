package com.example.sbomenricher.bom;

import static org.assertj.core.api.Assertions.assertThat;

import tools.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class BomParserTest {

  private final BomParser parser = new BomParser(new ObjectMapper());

  @Test
  void parse_extractsComponentsWithPurl() {
    String bom = """
        {
          "bomFormat": "CycloneDX",
          "components": [
            {"type": "library", "name": "jackson-databind", "version": "2.9.10",
             "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10"},
            {"type": "library", "name": "guava", "version": "33.0.0-jre",
             "purl": "pkg:maven/com.google.guava/guava@33.0.0-jre"}
          ]
        }
        """;

    List<SbomComponent> components = parser.parse(bom);

    assertThat(components).hasSize(2);
    assertThat(components.get(0).name()).isEqualTo("jackson-databind");
    assertThat(components.get(0).purl())
        .isEqualTo("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10");
  }

  @Test
  void parse_skipsComponentsWithoutPurl() {
    String bom = """
        {
          "components": [
            {"type": "library", "name": "no-purl-component", "version": "1.0.0"}
          ]
        }
        """;

    assertThat(parser.parse(bom)).isEmpty();
  }

  @Test
  void parse_missingComponentsArray_returnsEmptyList() {
    assertThat(parser.parse("{\"bomFormat\": \"CycloneDX\"}")).isEmpty();
  }

  @Test
  void parse_invalidJson_throwsIllegalArgumentException() {
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> parser.parse("not json"));
  }
}
