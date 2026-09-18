# Vendored dashboard JS

`htm-preact-standalone.module.js` — [htm](https://github.com/developit/htm) 3.1.1
`preact/standalone` build (preact + hooks + htm, ~13 KB), fetched from
`https://cdn.jsdelivr.net/npm/htm@3.1.1/preact/standalone.module.js`.

Vendored rather than CDN-loaded: the dashboard must work offline, and the served
page is `include_str!`-embedded in the binary. Served at `/preact.js`.

No build step: the dashboard uses `html` tagged templates, not JSX.
