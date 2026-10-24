# Build candidate 18 from source

Run from this draft root with Python 3 and a new output directory outside the draft:

```bash
python3 tools/build_project.py --output-dir /path/to/new-output-directory
```

The tool checks `src/FILES.json`, preserves modes and writes explicit directories
in the Debian archive. It installs nothing and does not compile native driver libraries.
Expected file: `gutochat-candidate-r18.deb`.

SHA-256: see / se SHA256SUMS in the release assets / utgivelsesvedleggene.

The companion source/build kit also includes driver wheels/sdists, protocol
definitions, libyaml/Google Protobuf sources, notices and upstream build recipes.
Library reassembly from verified wheels has been tested; native recompilation
was not performed. See the accompanying RELEASE_ASSETS.json and LICENSING.md.

## Isolated checks

Run `python3 tools/check.py`. Tests use synthetic data and do not open radios or production databases. Installer contracts mock host effects.
