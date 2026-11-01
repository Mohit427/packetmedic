---
version: 1
slug: "landing-src-app-tsx"
primary_target: "landing/src/App.tsx"
related_targets: []
---

# Landing page (packetmedic.streamlit.app, root route)

Scope: Persuade. Audience: hackathon judges evaluating in minutes; secondary: students/small offices downloading the Windows build. Action: download the Windows release (primary) or open the web demo (demonstration only). Proof: real engine output from the bundled synthetic samples, eval and test counts, real pmtui snapshot text. Constraints: embedded in Streamlit via components.html (no vh-based layout, self-resizing iframe, external links in new tabs, demo link via top navigation); no invented claims; synthetic data labelled; Windows Defender/SmartScreen section must be accurate (SmartScreen warning expected; Defender false positive possible, not observed).

## Direction contract

THESIS: A packet capture is a scan and PacketMedic is the radiologist. The page is a dark reading room whose lightbox carries real captures as backlit films, every finding circled in grease pencil with its verdict. It refuses the dark dev-tool hero with a terminal screenshot beside a headline.

OWN-WORLD: Reading-room wall near-black blue (#0b1016) as ground; lightbox glow blue-white (#eef5fa) as the major surface carrying headline ink in near-black; film = translucent dark emulsion with luminous tissue-white traces and grain; steel film clips; grease-pencil strokes. Palette law: red #ff4b3e = ATTACK, yellow #ffd23f = SUSPICIOUS, blue #4f8dff = FAULT, nothing else uses them. Type: Big Shoulders Display (signage), Atkinson Hyperlegible (body), JetBrains Mono (data only), Permanent Marker (grease pencil annotations only). Strict modular film-cell grid; one film, one statement.

STORY: The visitor sees one real capture where an outage and an attack overlap, reads two grease-pencil verdicts, understands that PacketMedic separates fault from attack with evidence, sees that the terminal app is the product (live capture, offline) and the web is a demo, learns why Windows may warn, and downloads.

FIRST VIEWPORT: Thin dark nav strip. Below it a full-width lightbox panel in a steel frame, switching on with a tube flicker. Top-left on the glow: headline in near-black condensed display at ~6rem, two lines, "Same broken network. Two different diagnoses." Sub-copy right of it. Lower 55%: one wide film clipped at the top, the real per-100ms packet trace of 11_mixed_outage_and_attack drawn as an X-ray, grease-pencil ring around the port-scan burst (ATTACK, red) and a bracket over the DNS timeouts (FAULT, blue), film label strip in mono. Primary action "Download for Windows" and secondary "Open the web demo" as lit film tabs at the lightbox's bottom edge. Hot-light spotlight follows the cursor across the film.

FORM: Radiology Reading Room, candidate 3 of 7 on the ordered list; seed key 13157c0c. Raises: one seed (real captures) drives every visual; strict modular film grid; palette law for verdict colours; one film one statement; time is the reading axis.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

Unresolved: none.
