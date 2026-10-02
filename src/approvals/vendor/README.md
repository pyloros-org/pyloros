# Vendored dashboard JS

`htm-preact-standalone.module.js` — [htm](https://github.com/developit/htm) 3.1.1
`preact/standalone` build (preact + preact/hooks + htm, ~13 KB), fetched from
`https://cdn.jsdelivr.net/npm/htm@3.1.1/preact/standalone.module.js`. Unmodified
except for the license header prepended to it.

Vendored rather than CDN-loaded: the dashboard must work offline, and the served
page is `include_str!`-embedded in the binary. Served at `/preact.js`.

No build step: the dashboard uses `html` tagged templates, not JSX.

## Licenses

The published bundle is minified with all notices stripped, so they are restored
here (both licenses require notice retention in redistributed copies):

- htm — Apache License 2.0, Copyright 2018 Google Inc. — `LICENSE.htm-Apache-2.0.txt`
- preact, preact/hooks — MIT, Copyright (c) 2015-present Jason Miller — `LICENSE.preact-MIT.txt`

Neither upstream package ships a `NOTICE` file, so Apache-2.0 §4(d) does not apply.
The licenses are also summarized in the header comment of the bundle itself, so a
copy of that single file carries its attribution.
