# Drift, oppgradering og avinstallasjon

Veiledning for kandidat18docs1. Ikke bruk prøvemaskinens private hjelpeskript som generelle installasjonsverktøy.

## Før oppgradering

Lukk GUI-vinduene for oppsettene som berøres. Ta kontrollert sikkerhetskopi av programversjon, innstillinger, radioregistrering og konsistente databaser. En kopi av bare en aktiv SQLite-hovedfil er ikke en fullverdig beskrivelse av en konsistent sikkerhetskopi. Den interne prøvebackupen er verifisert; en generell operativ gjenopprettingsprosedyre er fortsatt et åpent planpunkt.

Installer bare de verifiserte pakkene for den aktuelle utgivelsen. Kandidatens eksempel, fra mappen med pakkene:

```bash
sudo apt-get --no-remove install ./gutochat-candidate-r18.deb ./gutochat-driver-r4.deb
```

Ta med driveren bare hvis oppsettet bruker den og maskinen passer. Oppgraderingen stopper testoppsettene. Kontroller at pakkebehandleren ble ferdig uten feil før du gjenopptar. Ikke bruk gamle 13release1-/driver2-pakker; de hadde en kjent utpakkingsfeil.

## Gjenoppta

Åpne oppsettsveiviseren på lokalt skrivebord og velg riktig rolle → «Gjenoppta oppsett». Gjenoppta hver installerte rolle separat. Alternativt, for en allerede opprettet rolle:

```bash
sudo /usr/bin/python3 -I /usr/lib/gutochat-preview/admin.py resume base
```

Bytt siste ord til `field` ved behov. Kontroller Systemstatus, bevarte meldinger og eventuell radiokvittering/svar før vanlig drift fortsetter. En aktiv tjeneste alene beviser ikke at radioen svarer.

## Deaktiver eller fjern programmet

«Deaktiver oppsett» stopper den valgte rollen og beholder dens innstillinger og data. «Gjenoppta oppsett» tar den i bruk igjen. Avinstallasjon av programmet er en annen handling:

```bash
sudo apt-get remove gutochat-preview
```

Databevaring ved fjerning og reinstallasjon ble prøvd på den tidligere 12radio6-kandidaten. Det er ikke gjort en ny full fjerne-/reinstallasjonsprøve av 14. Kandidat14s oppgraderingsbevaring er kontrollert. Ikke slett datamapper manuelt, bruk purge, autoremove eller blind nedgradering som standard feilretting.

Innstillinger: `/etc/gutochat-preview/`. Rolledata: `/var/lib/gutochat-preview/data/base/` og `/var/lib/gutochat-preview/data/field/`. Disse kan inneholde privat informasjon og skal ikke legges i en offentlig GitHub-feilmelding eller kildepakke.
