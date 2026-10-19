/**
 * bridged-event-source — an EventSource for a served page under jsdom that
 * reads the REAL server's stream as a browser does (dashboard.md §4.8: a
 * service's logs fold). Mandu-new; moved here from
 * `tests/stack/inspector-service-logs-signed-out.test.ts` so the stack tests
 * of the logs fold share it.
 *
 * Each request carries `headers` (the reader's cookie and `Sec-Fetch-Site`).
 * A non-200 answer fails it for good (readyState CLOSED, then `error`, no
 * retry); a 200 stream's `event:`/`data:` frames reach its listeners. `cut()`
 * ends every one the returned class opened.
 */
export function bridgedEventSource(base: string, headers: Record<string, string>) {
  const open: AbortController[] = [];
  class BridgedEventSource {
    url: string;
    readyState = 0;
    onerror: ((ev: unknown) => void) | null = null;
    private fns = new Map<string, Array<(ev: { data: string }) => void>>();
    private ctl = new AbortController();
    constructor(url: string) {
      this.url = url;
      open.push(this.ctl);
      void this.run(new URL(url, base).href);
    }
    addEventListener(type: string, fn: (ev: { data: string }) => void): void {
      this.fns.set(type, [...(this.fns.get(type) ?? []), fn]);
    }
    close(): void {
      this.readyState = 2;
      this.ctl.abort();
    }
    private fail(): void {
      if (this.ctl.signal.aborted) return;
      this.readyState = 2;
      this.onerror?.({});
    }
    private async run(href: string): Promise<void> {
      let res: Response;
      try {
        res = await fetch(href, { headers, signal: this.ctl.signal });
      } catch {
        return this.fail();
      }
      if (res.status !== 200 || !String(res.headers.get("content-type")).startsWith("text/event-stream")) {
        await res.body?.cancel().catch(() => {});
        return this.fail();
      }
      this.readyState = 1;
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) return;
          buf += dec.decode(value, { stream: true });
          for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
            const frame = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let type = "message";
            const data: string[] = [];
            for (const l of frame.split("\n")) {
              if (l.startsWith("event:")) type = l.slice(6).trim();
              else if (l.startsWith("data:")) data.push(l.slice(5).replace(/^ /, ""));
            }
            if (data.length && !this.ctl.signal.aborted) for (const fn of this.fns.get(type) ?? []) fn({ data: data.join("\n") });
          }
        }
      } catch {
        /* cut */
      }
    }
  }
  return { EventSource: BridgedEventSource, cut: () => { for (const c of open.splice(0)) c.abort(); } };
}
