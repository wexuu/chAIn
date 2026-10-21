"""MCP integration: the tool logic (redacted reads, gated writes) and the
MCPServer wrapper. Agents operate chAIn through here; writes land as
proposals/candidates and are audited. Promotion stays human-only.
"""
