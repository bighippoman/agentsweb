import { blockedUrlReason } from "./url-guard.js";

export function publicUrl(raw: string): string | null {
  const blocked = blockedUrlReason(raw);
  if (blocked) return blocked;
  const url = new URL(raw);
  if (url.username || url.password) return "credentialed URLs are not public";
  if (
    [...url.searchParams.keys()].some((k) =>
      /^(token|access_token|api_?key|signature|sig|x-amz-.+|x-goog-.+)$/i.test(
        k,
      ),
    )
  )
    return "signed or credentialed URLs are not accepted by the public cache";
  if (url.port && !["80", "443"].includes(url.port)) return "unsupported port";
  return null;
}

/** Inspect every redirect and retain the signal until the body is consumed. */
export async function safeFetch(
  raw: string,
  init: RequestInit = {},
): Promise<Response> {
  let url = raw;
  const signal = init.signal
    ? AbortSignal.any([init.signal, AbortSignal.timeout(12_000)])
    : AbortSignal.timeout(12_000);
  for (let redirects = 0; redirects < 6; redirects++) {
    const reason = blockedUrlReason(url);
    if (reason) throw new Error(reason);
    const resp = await fetch(url, { ...init, redirect: "manual", signal });
    if (
      resp.status >= 300 &&
      resp.status < 400 &&
      resp.headers.has("location")
    ) {
      await resp.body?.cancel();
      const next = new URL(resp.headers.get("location")!, url).href;
      if (new URL(next).origin !== new URL(url).origin) {
        const headers = new Headers(init.headers);
        for (const key of [...headers.keys()])
          if (!["accept", "accept-language", "user-agent"].includes(key))
            headers.delete(key);
        init = { ...init, headers };
      }
      url = next;
      continue;
    }
    let bytes = 0;
    const body = resp.body?.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          bytes += chunk.byteLength;
          if (bytes > 5_000_000) throw new Error("response exceeds 5 MB limit");
          controller.enqueue(chunk);
        },
      }),
      { signal },
    );
    const result = new Response(body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    });
    Object.defineProperty(result, "url", { value: url });
    return result;
  }
  throw new Error("too many redirects");
}
