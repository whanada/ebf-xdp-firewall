# Project instructions

- Use the configured project owner Git identity for authorship and commits.
- Keep feature work on separate branches. Integration happens on integration.
- Merge development work into main when explicitly directed by the project owner.
  Production release still requires complete deployment and hardware acceptance.
  Skipped, unavailable and failed checks do not count as passes.
- Preserve explicit distinctions between native, generic and hardware-offloaded XDP.
- Use isolated network namespaces/veth interfaces for automated attachment tests.
- Do not claim confirmed TCP socket state from packet observations alone.
- Record compatibility limitations and unfinished production features honestly.
