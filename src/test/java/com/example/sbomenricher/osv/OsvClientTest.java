package com.example.sbomenricher.osv;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class OsvClientTest {

  @Test
  void queryByPurl_parsesVulnerabilitiesFromResponse() {
    RestClient.Builder builder = RestClient.builder();
    MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    OsvClient client = new OsvClient(builder.baseUrl("https://api.osv.dev"));

    server.expect(requestTo("https://api.osv.dev/v1/query"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(content().json("""
            {"package": {"purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10"}}
            """))
        .andRespond(withSuccess("""
            {
              "vulns": [
                {
                  "id": "GHSA-jjjh-jjxp-wpff",
                  "summary": "Deep wrapper array nesting can lead to DoS",
                  "severity": [{"type": "CVSS_V3", "score": "7.5"}]
                }
              ]
            }
            """, MediaType.APPLICATION_JSON));

    List<OsvVulnerability> vulns =
        client.queryByPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10");

    server.verify();
    assertThat(vulns).hasSize(1);
    assertThat(vulns.get(0).id()).isEqualTo("GHSA-jjjh-jjxp-wpff");
    assertThat(vulns.get(0).severity().get(0).score()).isEqualTo("7.5");
  }

  @Test
  void queryByPurl_noVulnerabilities_returnsEmptyList() {
    RestClient.Builder builder = RestClient.builder();
    MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    OsvClient client = new OsvClient(builder.baseUrl("https://api.osv.dev"));

    server.expect(requestTo("https://api.osv.dev/v1/query"))
        .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

    assertThat(client.queryByPurl("pkg:maven/com.example/clean-lib@1.0.0")).isEmpty();
  }
}
