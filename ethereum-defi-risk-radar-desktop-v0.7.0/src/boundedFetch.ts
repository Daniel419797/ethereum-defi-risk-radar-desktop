export async function fetchJsonBounded<T>(
  url: URL,
  init: RequestInit,
  opts: { timeoutMs: number; maxBytes: number }
): Promise<{ response: Response; payload: T; text: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("HTTP request timed out")), opts.timeoutMs);
  try {
    const signal = init.signal ? AbortSignal.any([controller.signal, init.signal]) : controller.signal;
    const response = await fetch(url, { ...init, signal });
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > opts.maxBytes) {
      controller.abort();
      throw new Error(`HTTP response exceeds ${opts.maxBytes} bytes`);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > opts.maxBytes) {
          controller.abort();
          throw new Error(`HTTP response exceeds ${opts.maxBytes} bytes`);
        }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder().decode(bytes);
    let payload: T;
    try { payload = JSON.parse(text) as T; }
    catch { throw new Error("HTTP response was not valid JSON"); }
    return { response, payload, text };
  } finally {
    clearTimeout(timer);
  }
}
