
export default async (req) => {
  if (req.method !== "POST") {
    return reply(405, { error: "Use POST to run an audit." });
  }

  try {
    const body = await req.json();
    const url = new URL(body.url);

    if (!["http:", "https:"].includes(url.protocol)) {
      return reply(400, { error: "Only HTTP and HTTPS URLs are supported." });
    }

    if (url.username || url.password) {
      return reply(400, { error: "URLs containing login credentials are not allowed." });
    }

    const host = url.hostname.toLowerCase();

    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host === "metadata.google.internal" ||
      isPrivateIPv4(host) ||
      host === "::1" ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      host.startsWith("fe80:")
    ) {
      return reply(400, { error: "That hostname is not allowed." });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response;

    try {
      response = await fetch(url.href, {
        signal: controller.signal,
        redirect: "error",
        headers: {
          "User-Agent": "SiteScanAI/1.0 (website audit)"
        }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return reply(400, {
        error: `The website returned HTTP ${response.status}.`
      });
    }

    const type = response.headers.get("content-type") || "";

    if (!type.includes("text/html")) {
      return reply(400, {
        error: "That URL did not return an HTML webpage."
      });
    }

    const html = (await response.text()).slice(0, 1000000);

    const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
    const descriptionMatch = html.match(
      /<meta\b(?=[^>]*\bname\s*=\s*["']description["'])(?=[^>]*\bcontent\s*=\s*["']([^"']*)["'])[^>]*>/i
    );
    const description = descriptionMatch
      ? (descriptionMatch[1] || "")
      : "";

    const title = titleMatch
      ? clean(titleMatch[1])
      : "";

    const h1Count = (html.match(/<h1\b[^>]*>/gi) || []).length;
    const imageTags = html.match(/<img\b[^>]*>/gi) || [];
    const imagesWithoutAlt = imageTags.filter(
      tag => !/\balt\s*=/i.test(tag)
    ).length;

    const linkTags = html.match(/<a\b[^>]*>/gi) || [];
    const linksWithoutNames = linkTags.filter(
      tag => !/\baria-label\s*=/i.test(tag) &&
        !/\btitle\s*=/i.test(tag)
    ).length;

    const checks = [
      {
        title: "Page title",
        status: title ? "PASS" : "ISSUE",
        details: title
          ? `Found the page title: "${title}".`
          : "No page title was found. Add a descriptive title."
      },
      {
        title: "Meta description",
        status: description ? "PASS" : "ISSUE",
        details: description
          ? "A meta description was found."
          : "No meta description was found. Add one to describe the page."
      },
      {
        title: "Main heading",
        status: h1Count === 1 ? "PASS" : "REVIEW",
        details: `Found ${h1Count} H1 headings. Review whether one clear main heading best describes the page.`
      },
      {
        title: "HTTPS",
        status: url.protocol === "https:" ? "PASS" : "ISSUE",
        details: url.protocol === "https:"
          ? "The submitted URL uses HTTPS."
          : "The submitted URL uses HTTP, not HTTPS."
      },
      {
        title: "Image alt attributes",
        status: imagesWithoutAlt === 0 ? "PASS" : "REVIEW",
        details: `${imagesWithoutAlt} of ${imageTags.length} image tags lack an alt attribute. Review whether meaningful alternative text is needed.`
      },
      {
        title: "Link accessibility",
        status: "REVIEW",
        details: `Found ${linksWithoutNames} links without an aria-label or title attribute. This is only a rough check; visible link text may already provide an accessible name.`
      }
    ];

    const passed = checks.filter(c => c.status === "PASS").length;
    const score = Math.round((passed / checks.length) * 100);

    return reply(200, {
      url: url.href,
      score,
      summary: `Completed ${checks.length} basic checks. This is an initial screening, not a full SEO, performance, or accessibility assessment.`,
      checks
    });
  } catch (error) {
    return reply(400, {
      error: error.name === "AbortError"
        ? "The website took too long to respond."
        : "Could not scan that website. Check the URL and try again."
    });
  }
};

function clean(value) {
  return value
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .trim()
    .slice(0, 300);
}

function isPrivateIPv4(host) {
  const parts = host.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)
  ) {
    return false;
  }

  const [a, b] = parts;

  return a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127);
}

function reply(statusCode, data) {
  return new Response(JSON.stringify(data), {
    status: statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}
