import type { TinyFishSearchResponse } from "./types.js";
import { fetchJsonBounded } from "./boundedFetch.js";

export class TinyFishSearchClient {
  private readonly apiKey: string;
  private readonly endpoint: string;

  constructor(opts: { apiKey: string; endpoint?: string }) {
    if (!opts.apiKey) throw new Error("TINYFISH_API_KEY is required");
    this.apiKey = opts.apiKey;
    this.endpoint = opts.endpoint ?? "https://api.search.tinyfish.ai";
  }

  async search(input: {
    query: string;
    purpose?: string;
    language?: string;
    afterDate?: string;
    beforeDate?: string;
    page?: number;
    includeDomains?: string[];
    excludeDomains?: string[];
  }): Promise<TinyFishSearchResponse> {
    const url = new URL(this.endpoint);

    url.searchParams.set("query", input.query);
    if (input.purpose) url.searchParams.set("purpose", input.purpose);
    if (input.language) url.searchParams.set("language", input.language);
    if (input.afterDate) url.searchParams.set("after_date", input.afterDate);
    if (input.beforeDate) url.searchParams.set("before_date", input.beforeDate);
    if (typeof input.page === "number") {
      url.searchParams.set("page", String(input.page));
    }
    if (input.includeDomains?.length) {
      url.searchParams.set("include_domains", input.includeDomains.join(","));
    }
    if (input.excludeDomains?.length) {
      url.searchParams.set("exclude_domains", input.excludeDomains.join(","));
    }

    const { response, payload, text } = await fetchJsonBounded<TinyFishSearchResponse>(url, {
      method: "GET",
      headers: {
        "X-API-Key": this.apiKey,
        "Accept": "application/json"
      }
    }, { timeoutMs: 30_000, maxBytes: 2_000_000 });

    if (!response.ok) {
      throw new Error(
        `TinyFish Search failed: HTTP ${response.status} ${text.slice(0, 500)}`
      );
    }

    return payload;
  }
}
