# Security Policy

## Supported versions

Security fixes land on the default branch (`main`). There are no long-lived release trains yet.

## Threat model (short)

`ghidra-mcp` is a local reverse-engineering bridge:

1. An MCP client talks to the **Rust bridge** over **stdio**.
2. The bridge calls a **Ghidra plugin HTTP server**, which defaults to **`127.0.0.1` only**.
3. Several tools can **mutate the open program**, **write live process memory**, or **evaluate code** inside Ghidra / an attached process.

Anyone who can reach the plugin HTTP port (or drive the MCP client) can exercise those capabilities. Treat the stack as **trusted-local**, not multi-tenant SaaS.

## Hardening checklist

| control | recommendation |
| --- | --- |
| Bind address | Keep **`127.0.0.1`**. Do not bind `0.0.0.0` / public interfaces. |
| Auth token | Set **Auth Token** in Ghidra Tool Options and pass the same value via `--ghidra-token` / `GHIDRA_TOKEN`. |
| File IO | Leave **File IO Directory** empty unless you need import/export/`write_artifact`. |
| Powerful tools | Restrict who can run `ghidra_eval`, live write tools, `lua_exec`, and patch helpers. |
| Bridge binary | Point MCP configs at a binary you built or verified yourself. |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for exploitable security bugs.

1. Email or privately contact the maintainer via GitHub: [@imjustprism](https://github.com/imjustprism)
2. Include:
   - affected component (bridge / plugin / script)
   - version or commit
   - reproduction steps
   - impact (RCE, data exfil, auth bypass, …)
3. Allow a reasonable window for a fix before public disclosure.

We will acknowledge reports and coordinate a fix or public advisory as appropriate.

## Out of scope (examples)

- Using the tools to reverse or modify third-party software (intended use of an RE toolkit)
- Issues that only appear when the plugin is intentionally bound to a non-loopback interface without auth
- Vulnerabilities solely in Ghidra, MCP clients, or the OS debugger stack
