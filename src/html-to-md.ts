import { parseHTML } from "linkedom";
import TurndownService from "turndown";

export function convertHtmlToMarkdown(
  html: string,
  baseUrl = "https://example.org/",
): string {
  const { document } = parseHTML(html);
  document
    .querySelectorAll(
      'script,style,nav,footer,aside,form,iframe,noscript,[aria-hidden="true"],[role="navigation"],[role="banner"],.cookie-banner,.cookie-consent',
    )
    .forEach((n: { remove(): void }) => n.remove());
  const root =
    document.querySelector("article") ||
    document.querySelector("main") ||
    document.querySelector('[role="main"]') ||
    document.querySelector(
      ".markdown-body,.prose,.entry-content,.post-content",
    ) ||
    document.body;
  for (const link of root.querySelectorAll("a[href]")) {
    try {
      const url = new URL(link.getAttribute("href")!, baseUrl);
      if (["http:", "https:"].includes(url.protocol))
        link.setAttribute("href", url.href);
      else link.removeAttribute("href");
    } catch {
      link.removeAttribute("href");
    }
  }
  for (const img of root.querySelectorAll("img[src]")) {
    try {
      img.setAttribute("src", new URL(img.getAttribute("src")!, baseUrl).href);
    } catch {
      img.remove();
    }
  }
  const td = new TurndownService({
    headingStyle: "atx",
    codeBlockStyle: "fenced",
    bulletListMarker: "-",
  });
  td.addRule("tables", {
    filter: "table",
    replacement: (_content, node) => {
      const rows = Array.from(node.querySelectorAll("tr")).map((row) =>
        Array.from(row.querySelectorAll("th,td")).map((cell) =>
          td
            .turndown(cell as HTMLElement)
            .replace(/\|/g, "\\|")
            .replace(/\n/g, " "),
        ),
      );
      if (!rows.length) return "";
      const width = Math.max(...rows.map((row) => row.length));
      const lines = rows.map(
        (row) =>
          "| " +
          [...row, ...Array(width - row.length).fill("")].join(" | ") +
          " |",
      );
      lines.splice(1, 0, "| " + Array(width).fill("---").join(" | ") + " |");
      return "\n\n" + lines.join("\n") + "\n\n";
    },
  });
  let markdown = td
    .turndown(root as Parameters<TurndownService["turndown"]>[0])
    .trim();
  const title = document.querySelector("title")?.textContent?.trim();
  if (title && !/^# /m.test(markdown)) markdown = `# ${title}\n\n${markdown}`;
  return markdown;
}
