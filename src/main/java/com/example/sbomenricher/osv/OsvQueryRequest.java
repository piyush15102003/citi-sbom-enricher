package com.example.sbomenricher.osv;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Request body for {@code POST https://api.osv.dev/v1/query}. */
public record OsvQueryRequest(@JsonProperty("package") OsvPackage pkg) {
}
