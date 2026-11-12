# Project instructions

- Use the configured human Git identity. Never author or co-author commits as Codex.
- Keep feature work on separate branches. Integration happens on codex/integration.
- Do not merge into main until the complete application and deployment have run
  successfully on this computer and all required acceptance checks are recorded.
  Skipped, unavailable and failed checks do not count as passes.
- Preserve explicit distinctions between native, generic and hardware-offloaded XDP.
- Use isolated network namespaces/veth interfaces for automated attachment tests.
- Do not claim confirmed TCP socket state from packet observations alone.
- Record compatibility limitations and unfinished production features honestly.
