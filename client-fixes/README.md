# Client fixes

Enable **Client fixes** in the launcher's Settings to load this DLL. The
**Client fixes debug window** option controls its diagnostic console on the
next game launch and is off by default. Diagnostics still go to an attached
debugger when the window is hidden.

- **Local class selection:** Unlocks all current classes in standalone local
  games by temporarily raising the local player's class eligibility level to
  5. Online matches are excluded.
- **White and Gold Super Capsules:** Corrects their merged item table buff IDs
  so both capsules can be used. The DLL verifies the original IDs and the
  replacement buff rows before changing either value, then reapplies the fix
  if the table is rebuilt.
- **First Blood audio:** Lets the first cue play in a local match, suppresses
  later bot first-kill cues, and re-arms it for the next match. It checks the
  loaded perk widget script and sound assets before changing the audio
  reference. The 25 ms widget poll can miss exceptionally close kills.
- **Cheat Widget translation (disabled):** The translation implementation is retained,
  but its worker is not started. This allows testing a cooked PAK replacement
  without the DLL changing the table in memory.

- **Signed ClientFixes PAK:** Adds a separate public RSA key for the exact file
  `BravoHotelGame/Content/Paks/BravoHotelGame-ClientFixes_P.pak`. Its matching
  `.sig` authenticates a SHA-256 digest of the complete PAK and its chunk CRC
  table, with a ClientFixes-specific signing domain. The engine retains its
  chunk integrity checks. Every other PAK path uses the original validator and
  original key. This authenticates the custom patch; it is not server-side
  anti-cheat enforcement.

The hook starts only after the executable SHA-256 check passes and additionally
checks all 19 bytes of the researched validator prologue. It pauses existing
threads during the patch and refuses installation if any are executing in that
prologue or cannot be checked. The signing key in source is public only; the
private key must stay outside repositories and build artifacts. A successful
verification holds a read-only sharing handle to the patch until process exit.
The DLL remains loaded until process exit, as required by the existing worker
lifetime model. DLL translations remain disabled.

Build and verification run through the existing Windows GitHub Action. CTest
uses a synthetic signed fixture and checks rejection of modified PAK bytes,
modified CRCs, modified signatures and malformed lengths. These tests verify
Windows cryptography and file verification; they do not establish live engine
compatibility of the hook or sidecar parsing.
When the custom PAK is present, the supported-build worker keeps the researched
`PakFile.SearchRecentlyFoundPaks` integer at zero, checking every 250 ms to
recover from later config writes. The registration and lookup instructions are
validated before enabling this control. Diagnostics report observed changes.
This makes PAK lookup follow mount priority and may increase asset lookup cost.
The preserved shipping executable contains no ASCII or UTF-16 `ExecCmds` literal;
startup-command handling is therefore not relied upon for this setting.

With the client-fixes debug console enabled, the build-checked CheatTable lookup
diagnostic reports the original Find result, archive name, mount root, and current
cache value. It logs custom-archive misses and successful/deleted entries from
other archives, up to 64 messages. It does not alter lookup results. The extra
lookup hook is omitted when the debug console setting is off.

