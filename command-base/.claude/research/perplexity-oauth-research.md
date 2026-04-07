# Perplexity OAuth & Cost Avoidance Research

**Researcher:** Pax
**Date:** 2026-03-26
**Status:** Complete

---

## Executive Summary

**Can Max use Perplexity Pro via OAuth/token to avoid API costs? YES -- but not through OAuth.**

Perplexity does NOT offer OAuth for programmatic API access. However, there are mature, well-maintained MCP servers that use **browser session cookies** to pipe queries through the Perplexity web interface, effectively leveraging a Pro subscription ($20/month) for unlimited queries with zero API costs. This is exactly analogous to how Claude Code uses OAuth to leverage a Claude subscription.

**Recommended solution:** `mishamyrt/perplexity-web-api-mcp` -- a one-command install into Claude Code.

---

## 1. Does Perplexity Support OAuth?

**For programmatic API access: NO.**

Perplexity's API uses only **bearer token (API key) authentication**. There is no OAuth flow that lets you authenticate as a Pro subscriber and make API calls against your subscription.

What Perplexity *does* have:
- **API Keys**: The only official method for programmatic access. Generated at `docs.perplexity.ai`. Format: `pplx-[alphanumeric]`.
- **Enterprise SSO**: Built on OAuth 2.0/OIDC, but only for *logging into the Perplexity web app* -- not for API access.
- **OAuth for MCP Connectors** (March 2026): Pro/Max/Enterprise users can connect external tools TO Perplexity via MCP with OAuth auth. This is the reverse direction -- Perplexity calling out, not you calling in.

**Bottom line:** No OAuth equivalent to Claude Code's `claude login` flow exists for Perplexity.

---

## 2. Can You Use a Pro Subscription Programmatically?

**Yes, via session token extraction.** This is the key finding.

The Perplexity web app uses NextAuth.js for session management. By extracting the session cookies from your browser, you can make requests that are authenticated as your Pro account -- getting the same unlimited Pro queries you'd get in the browser, but programmatically.

**Required cookies:**
- `__Secure-next-auth.session-token` (or `next-auth.session-token`)
- `next-auth.csrf-token`

**Token lifespan:** NextAuth.js defaults to 30-day session tokens with rolling expiry (resets on activity). In practice, as long as you're using Perplexity regularly (via browser or MCP), the tokens stay valid. You'll need to re-extract them occasionally (likely monthly).

---

## 3. Authentication Methods Perplexity Offers

| Method | For What | Cost Model |
|--------|----------|------------|
| **API Keys** | Official API (Sonar, Search API) | Pay-per-query/token |
| **Enterprise SSO** | Web app login | Subscription |
| **Session Cookies** | Web interface (unofficial) | Subscription (unlimited Pro queries) |
| **Account Generator** | Automated fresh accounts (helallao lib) | Free tier limits |

---

## 4. Ways to Use Perplexity Pro Without API Costs

### Option A: `mishamyrt/perplexity-web-api-mcp` (RECOMMENDED)

The best option. A purpose-built MCP server that uses session tokens to access Perplexity's web interface.

**Install in Claude Code (one command):**
```bash
claude mcp add perplexity \
  --env PERPLEXITY_SESSION_TOKEN="your-session-token" \
  --env PERPLEXITY_CSRF_TOKEN="your-csrf-token" \
  -- npx -y perplexity-web-api-mcp
```

**How to get tokens:**
1. Log into perplexity.ai in your browser
2. Open DevTools (F12) -> Application -> Cookies -> https://www.perplexity.ai
3. Copy `__Secure-next-auth.session-token` -> `PERPLEXITY_SESSION_TOKEN`
4. Copy `next-auth.csrf-token` -> `PERPLEXITY_CSRF_TOKEN`

**Tools provided:**
- `perplexity_search` -- Quick web search (links, titles, snippets only)
- `perplexity_ask` -- Full answer with source citations (uses Pro models when authenticated)
- `perplexity_reason` -- Advanced reasoning and problem-solving
- `perplexity_research` -- Deep research using sonar-deep-research model

**Model selection (configurable via env vars):**
- Ask models: turbo, pro-auto, sonar, gpt-5.4, claude-4.6-sonnet, nemotron-3-super
- Reason models: gemini-3.1-pro, gpt-5.4-thinking, claude-4.6-sonnet-thinking

**Pros:**
- Zero API costs -- uses your Pro subscription
- Clean MCP integration with Claude Code
- Supports all Pro features (search, reasoning, deep research)
- MIT licensed, actively maintained
- Works even without tokens (limited tokenless mode)

**Cons:**
- Unofficial -- could break if Perplexity changes their web app
- Session tokens expire (~30 days, need periodic refresh)
- No structured result format like the official API

**GitHub:** https://github.com/mishamyrt/perplexity-web-api-mcp
**Docs:** https://mishamyrt.github.io/perplexity-web-api-mcp/

---

### Option B: `wysh3/perplexity-mcp-zerver`

Uses **browser automation** (Puppeteer) instead of session cookies.

**Setup:**
```bash
# Clone and build
git clone https://github.com/wysh3/perplexity-mcp-zerver
cd perplexity-mcp-zerver
bun install && bun run build

# Login (for Pro features)
bun run login  # authenticates via email
```

**Pros:** Persistent browser profile, no manual cookie extraction
**Cons:** Heavier (runs a browser), slower than direct API, marked "educational use only"

**GitHub:** https://github.com/wysh3/perplexity-mcp-zerver

---

### Option C: `helallao/perplexity-ai` (Python Library)

A full Python wrapper around Perplexity's web interface.

**Usage:**
```python
from perplexity import Client
client = Client(cookies={"next-auth.session-token": "your-token"})
result = client.search("your query", mode="pro")
```

**Features:** Sync/async, streaming, file uploads, Pro/Reasoning/Deep Research modes
**Also includes:** MCP server (`pip install -e ".[mcp]"`)
**Also includes:** Account generator via Emailnator (generates fresh free accounts)

**GitHub:** https://github.com/helallao/perplexity-ai

---

### Option D: Browser Automation (Playwright/Puppeteer)

Roll your own with Playwright hitting perplexity.ai directly. Max already has Playwright MCP available.

**Pros:** Full control, no dependencies on third-party wrappers
**Cons:** Most effort to build, slowest, most fragile

---

## 5. Cost Comparison

### Perplexity Pro Subscription (via session token MCP)
| Item | Cost |
|------|------|
| Monthly subscription | $20/month |
| Per-query cost | $0 (unlimited Pro queries) |
| Deep Research | Included |
| 100 queries/day | $20/month total |
| 1,000 queries/day | $20/month total |

### Perplexity API (Official, Pay-Per-Query)
| Model | Cost per query (typical) |
|-------|------------------------|
| Sonar (basic search) | ~$0.005-0.012 per query |
| Sonar Pro | ~$0.006-0.014 per query + $15/M output tokens |
| Search API (raw results) | $0.005 per query |
| Sonar Deep Research | ~$0.41 per query (example with 7K output tokens) |

### What Max Would Actually Spend (API route)

Assuming moderate usage for The Team (50 searches/day):
- **Basic Sonar searches:** 50 x $0.01 avg = $0.50/day = ~$15/month
- **Mix with some Pro/Deep Research:** Could easily hit $30-60/month
- **Heavy usage:** $100+/month

### What Max Would Spend (Session Token MCP route)
- **Any usage level:** $20/month flat (Pro subscription)

### Pro Subscription API Credits
- Pro includes $5/month in API credits -- negligible for real usage
- API billing is completely separate from subscription

---

## 6. MCP Servers for Perplexity (Complete List)

### Official
| Server | Auth | Notes |
|--------|------|-------|
| [perplexityai/modelcontextprotocol](https://github.com/perplexityai/modelcontextprotocol) | API Key | Official. Requires paid API credits. |

### Session-Token Based (No API Costs)
| Server | Auth | Notes |
|--------|------|-------|
| [mishamyrt/perplexity-web-api-mcp](https://github.com/mishamyrt/perplexity-web-api-mcp) | Session cookies | **Best option.** TypeScript/Node. One-line Claude Code install. |
| [helallao/perplexity-ai](https://github.com/helallao/perplexity-ai) | Session cookies | Python. Full wrapper + MCP server. Also has account generator. |
| [wysh3/perplexity-mcp-zerver](https://github.com/wysh3/perplexity-mcp-zerver) | Browser automation | TypeScript/Bun. Puppeteer-based. Heavier but no cookie extraction. |

### API-Key Based (Community)
| Server | Language | Notes |
|--------|----------|-------|
| [cyanheads/perplexity-mcp-server](https://github.com/cyanheads/perplexity-mcp-server) | TypeScript | showThinking support |
| [daniel-lxs/mcp-perplexity](https://github.com/daniel-lxs/mcp-perplexity) | Python | Chat history, conversation management |
| [Alcova-AI/perplexity-mcp](https://github.com/Alcova-AI/perplexity-mcp) | Go | Claude Code/Desktop focused |
| [jsonallen/perplexity-mcp](https://github.com/jsonallen/perplexity-mcp) | TypeScript | Basic web search |
| [DaInfernalCoder/perplexity-mcp](https://github.com/DaInfernalCoder/perplexity-mcp) | TypeScript | Auto query complexity detection |

---

## 7. Recommendation

**Use `mishamyrt/perplexity-web-api-mcp` with a Perplexity Pro subscription.**

**Setup steps:**
1. Subscribe to Perplexity Pro ($20/month) if not already
2. Log into perplexity.ai in browser
3. Extract session tokens from DevTools cookies
4. Run: `claude mcp add perplexity --env PERPLEXITY_SESSION_TOKEN="..." --env PERPLEXITY_CSRF_TOKEN="..." -- npx -y perplexity-web-api-mcp`
5. Re-extract tokens monthly (or when they expire)

**This gives The Team:**
- Unlimited Perplexity Pro queries at $20/month flat
- Search, ask, reasoning, and deep research tools in Claude Code
- Access to frontier models (GPT-5.4, Claude 4.6 Sonnet, etc.) through Perplexity
- Zero per-query API costs
- Same pattern as Claude Code's own OAuth -- subscription-based, not credit-based

**Risk:** This is unofficial. Perplexity could change their web app and break it. But the MCP is actively maintained and the pattern is well-established (multiple independent implementations exist).

---

## Sources

- [Perplexity API Pricing](https://docs.perplexity.ai/docs/getting-started/pricing)
- [Perplexity Subscription Plans](https://www.getaiperks.com/en/articles/perplexity-pricing)
- [Perplexity Web API MCP - GitHub](https://github.com/mishamyrt/perplexity-web-api-mcp)
- [Perplexity Web API MCP - Docs](https://mishamyrt.github.io/perplexity-web-api-mcp/)
- [Perplexity AI Unofficial Wrapper - GitHub](https://github.com/helallao/perplexity-ai)
- [Perplexity MCP Zerver - GitHub](https://github.com/wysh3/perplexity-mcp-zerver)
- [Official Perplexity MCP Server - GitHub](https://github.com/perplexityai/modelcontextprotocol)
- [Perplexity Generate Auth Token API](https://docs.perplexity.ai/api-reference/generate-auth-token-post)
- [Perplexity SSO Integration](https://www.perplexity.ai/help-center/en/articles/11200832-sso-integration-getting-started)
- [Perplexity API Settings](https://www.perplexity.ai/help-center/en/articles/10352995-api-settings)
- [NextAuth.js Session Configuration](https://next-auth.js.org/configuration/options)
