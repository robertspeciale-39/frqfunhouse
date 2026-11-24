# The FRQ Funhouse

Five games that teach the AP Cybersecurity free-response question (Device Security Analysis), plus a World's Fair splash page.

| Folder | Game |
|---|---|
| `index.html` | Splash page (the fairground) |
| `reading-room/` | Point / No Point: score sample answers like an AP Reader |
| `evidence-locker/` | Evidence Locker: pin source lines, build claim + reasoning |
| `verb-lock/` | Verb Lock: task-verb game show + chmod lightning rounds |
| `trap-door/` | Trap Door: 12 chambers of classic point-killers |
| `mission-clock/` | Mission Clock: full timed FRQ with pacing coach + PDF report |
| `shared/cases.js` | The two practice device cases (sources, parts A–E, rules, model answers) |
| `shared/common.js` | Helpers (chmod checker, saving, source rendering) |

## Deploy
Upload the whole folder to one GitHub repo and import it into Vercel as a static site (no build step, framework "Other"). Keep the folder structure: the games load `../shared/*.js`.

## Edit content
- Practice cases (used by Evidence Locker + Mission Clock): `shared/cases.js`. Copy one case object to add a third device.
- Reading Room items: the `ITEMS` and `FIXES` arrays near the top of `reading-room/index.html`.
- Verb Lock rounds: `PICKS` and `WRITES` in `verb-lock/index.html`.
- Trap Door chambers: `ROOMS` in `trap-door/index.html`.
- If you type `</script>` inside a string in an HTML file, write it as `<\/script>`.

Progress and best scores are saved in the student's browser only (localStorage). Reports print to PDF with the browser's "Save as PDF".
