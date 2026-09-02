package com.example.sbomenricher.web;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(EnrichController.class)
class EnrichControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private EnrichmentService enrichmentService;

  @Test
  void enrich_returnsAnnotatedComponentsAsJson() throws Exception {
    given(enrichmentService.enrich(anyString())).willReturn(List.of(
        new EnrichedComponent("jackson-databind", "2.9.10",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10",
            List.of(new EnrichedComponent.VulnerabilitySummary(
                "GHSA-jjjh-jjxp-wpff", "Deep wrapper array nesting can lead to DoS", "7.5")))));

    mockMvc.perform(post("/enrich")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"components\": []}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].name").value("jackson-databind"))
        .andExpect(jsonPath("$[0].vulnerabilities[0].id").value("GHSA-jjjh-jjxp-wpff"))
        .andExpect(jsonPath("$[0].vulnerabilities[0].severity").value("7.5"));
  }
}
