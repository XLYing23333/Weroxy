# Third-party notice inventory

`third_party.json` records pinned package identities, application scopes, upstream
license/NOTICE/PATENTS texts, their hashes and evidence sources. It contains no
runtime code and is not required on installed hosts.

The generated outputs are:

- `THIRD_PARTY_NOTICES`: combined repository inventory.
- `WeroxyServer/THIRD_PARTY_NOTICES`: all 13 declared Go modules, Go runtime and
  standard-library vendor notices, and all 126 npm lock entries. This includes
  build tools and optional platform artifacts; listing them does not mean they
  are executed by the installed Server.
- `WeroxyClient/THIRD_PARTY_NOTICES`: its 3 declared Go modules and Go runtime /
  standard-library vendor notices. Web dependencies are not embedded in Client.

Both modules embed their own output. Native Client packages install the Client
output in their documentation; Server images and release archives include the
Server output. CLI, TUI and Web viewing entries use these same texts.

Check offline from the repository root:

```sh
python3 scripts/third_party_notices.py --check
```

After dependency updates, install the locked npm dependencies and populate the
Go module cache, then regenerate using the pinned Go executable:

```sh
GO=/path/to/go python3 scripts/third_party_notices.py --update
```

Regeneration reads installed upstream legal files, not just SPDX identifiers.
For platform esbuild/Rollup packages that omit their own legal file, it records
the same-version parent distribution's license texts. For Vue devtools-api it
reads the upstream version tag; for the uninstalled fsevents platform package,
it verifies the tarball against the npm lock integrity before reading its license.
No downloaded install scripts or package code are executed by this generator.
Review regenerated source evidence and text changes before release.

The generator checks Go module declarations and npm lock entries, including
indirect dependencies, but does not claim a file-by-file copyright audit of all
upstream implementations. Upstream bundled third-party notice files (such as
modernc libc, TypeScript, Vite, Rollup and ECharts NOTICE) are retained. Compiler
executables, Docker build-image OS packages and optional system-installed host
tools remain their distributors' packages and are outside the installed-app
inventory. RAW reference sources are not shipped.

## Missing upstream full texts

Two locked packages declare MIT in their published metadata but supply no full
license/copyright file:

- `lodash-unified@1.0.3`: npm tarball contains only four implementation/metadata
  files and no license. No repository is declared in its published metadata.
- `@napi-rs/lzma-linux-x64-gnu@1.5.1`: the platform package provides no legal file;
  its declared upstream release commit
  `f164df92d83e095f195d628b1a68a141ae2eb638` also has no root license file.

Their publisher metadata is included explicitly as metadata-only evidence.
The inventory does not fabricate missing copyright statements or certify these
upstream omissions resolved. `--check` reports the omissions on every run.
