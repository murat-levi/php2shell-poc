"""lib/ — internal modules for the php2shell toolkit.

Submodules:
  transport      JA3/TLS stealth HTTP client (curl_cffi with urllib fallback)
  detect         non-destructive version + prerequisite detection
  preflight      exploit readiness scoring
  oomprobe       active OOM detection (assetnote-style)
  reporter       JSON / CSV / table output
  banner         CLI banner / ASCII art
  chain          exploit engine wrapper (delegates to exploit/ scripts)
  exploit_runner orchestration of the 5 exploit chains
"""

__all__ = [
    "transport", "detect", "preflight", "oomprobe", "reporter",
    "banner", "chain", "exploit_runner",
]
