# Bygge kandidat 18 fra kilde

Kjør fra denne kladdens rot med Python 3 og en ny utmappe utenfor kladden:

```bash
python3 tools/build_project.py --output-dir /path/to/new-output-directory
```

Verktøyet kontrollerer `src/FILES.json`, filmoduser og bygger Debian-arkivet med
eksplisitte mapper. Det installerer ingenting og kompilerer ikke native driverbiblioteker.
Forventet fil: `gutochat-candidate-r18.deb`.

SHA-256: see / se SHA256SUMS in the release assets / utgivelsesvedleggene.

Den samsvarende kilde-/byggpakken har også driverens hjul- og kildearkiver,
protokolldefinisjoner, libyaml-/Google Protobuf-kilder, notices og byggeoppskrifter.
Driverbibliotekene kan settes sammen fra de verifiserte hjulfilene; native
nykompilering er ikke utført i dette arbeidet. Se RELEASE_ASSETS.json utenfor
repository-kladden og lisensoversikten i LISENS_NO.md.

## Isolerte prøver

Kjør `python3 tools/check.py`. Prøvene bruker syntetiske data og åpner ikke radioer eller driftsdatabaser. Installasjonsprøvene bruker simulerte systemhandlinger.
