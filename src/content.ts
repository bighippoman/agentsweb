import type { Passage } from "./types.js";

export async function hash(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(bytes), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** Quality heuristics are not a prompt-injection security boundary. */
export function contentProblem(markdown: string): string | null {
  if (markdown.length < 200) return "insufficient readable content";
  if (markdown.length > 1_000_000) return "document exceeds 1 MB text limit";
  const head = markdown.slice(0, 1800);
  if (
    /(?:complete|solve|enter|verify).{0,30}captcha|checking your browser|please verify you are human|enable javascript and cookies|^\s*access denied\s*$/im.test(
      head,
    )
  )
    return "challenge page";
  if (
    /sign in to continue|log in to continue|subscribe to (read|continue)/i.test(
      head,
    )
  )
    return "access wall";
  const words = markdown.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) ?? [];
  if (words.length > 200 && new Set(words).size / words.length < 0.03)
    return "repetitive content";
  return null;
}

export function passages(markdown: string, url: string): Passage[] {
  const result: Passage[] = [];
  let start = 0;
  let heading = markdown.match(/^#\s+(.+)/m)?.[1] ?? new URL(url).hostname;
  while (start < markdown.length) {
    let end = Math.min(start + 6000, markdown.length);
    if (end < markdown.length) {
      const boundary = markdown.lastIndexOf("\n\n", end);
      if (boundary > start + 2000) end = boundary;
    }
    const window = markdown.slice(start, end);
    const text = window.trim();
    const textStart = start + window.length - window.trimStart().length;
    const headings = [...text.matchAll(/^#{1,6}\s+(.+)/gm)];
    if (headings.length) heading = headings[0][1];
    const quote = text
      .replace(/^#+\s+/gm, "")
      .replace(/[*`_\[\]]/g, "")
      .replace(/\s+/g, " ")
      .slice(0, 100);
    if (text.length > 40)
      result.push({
        url,
        heading,
        text,
        start: textStart,
        end: textStart + text.length,
        citation_url: `${url.split("#")[0]}#:~:text=${encodeURIComponent(quote)}`,
      });
    start = end === markdown.length ? end : end - 180;
  }
  return result;
}

export function ftsQuery(query: string): string {
  const words = query.match(/[\p{L}\p{N}_]{2,}/gu)?.slice(0, 16) ?? [];
  return words.map((w) => `"${w}"`).join(" AND ");
}

export function selectSection(markdown: string, query: string): string | null {
  const headings = [...markdown.matchAll(/^(#{1,6})\s+(.+)$/gm)];
  const index = headings.findIndex((h) =>
    h[2].toLowerCase().includes(query.toLowerCase()),
  );
  if (index < 0) return null;
  const next = headings
    .slice(index + 1)
    .find((h) => h[1].length <= headings[index][1].length);
  return markdown
    .slice(headings[index].index, next?.index ?? markdown.length)
    .trim();
}

/** Readable MDX/native Markdown; preserve code and resolve relative source links. */
export function cleanMarkdown(text: string, url: string): string {
  const frontmatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  const title = frontmatter?.[1].match(/^title:\s*["']?(.+?)["']?$/m)?.[1];
  if (frontmatter) text = text.slice(frontmatter[0].length);
  let fenced = false;
  text = text
    .split("\n")
    .map((line) => {
      if (/^\s*```/.test(line)) {
        fenced = !fenced;
        return line;
      }
      if (fenced) return line;
      if (/^\s*<\/?[A-Z][A-Za-z]*(?:\s[^>]*)?\s*\/?>\s*$/.test(line)) return "";
      return line
        .replace(
          /<\/?(?:Intro|CodeStep|DeepDive|YouWillLearn|Recap|InlineToc|Sandpack|Recipes|Solution|Pitfall)\b[^>]*>/g,
          "",
        )
        .replace(/\s*\{\/\*.*?\*\/\}/g, "")
        .replace(/\]\(([^)\s]+)\)/g, (all, href) => {
          try {
            return "](" + new URL(href, url).href + ")";
          } catch {
            return all;
          }
        });
    })
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (title && !/^# /m.test(text)) text = `# ${title}\n\n${text}`;
  return text;
}
