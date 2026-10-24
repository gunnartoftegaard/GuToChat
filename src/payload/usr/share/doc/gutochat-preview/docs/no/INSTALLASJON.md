# Installere prøveutgaven

Veiledning for kandidat 18docs1 (ikke installert ennå) med driver 4. Materialet er klargjort lokalt; offentlig nedlasting er ikke opprettet.

## Det du trenger

Den dokumenterte fysiske prøven gjelder Raspberry Pi 5 med 64-bit Debian 13, Python 3.13, systemd og et lokalt skrivebord. Bruk en vanlig brukerkonto med adgang til administratorbekreftelse. Andre Raspberry Pi-modeller, 32-bit og øvrige operativsystemer er ikke godkjent gjennom denne prøven. Pakken tillater også Ubuntu 24.04, men denne rapporten fastsetter ikke samme maskinvareaksept der.

Du trenger ingen Waveshare-, Meshtastic- eller RTL-SDR-enhet for å installere og åpne grunnoppsettet. Uten radioadapter har oppsettet ingen radiomeldingsvei. Du kan installere Base, Field eller begge; de har separate innstillinger og data. Base/Field-rollen er ikke et krav om en bestemt radiomodell.

## Installer grunnpakken

Bruk bare pakker med kontrollsummer fra den samme utgivelsen. Åpne Terminal i mappen der den kontrollerte pakken ligger, og kjør:

```bash
sudo apt-get --no-remove install ./gutochat-candidate-r18.deb
```

Kommandoen er for denne kandidatens filnavn. Skriv ditt eget administratorpassord lokalt. Pakkebehandleren kan hente oppførte systemavhengigheter fra operativsystemets pakkekilder. Avbryt og undersøk hvis den foreslår uventet fjerning eller andre store endringer. Ikke kopier interne testhjelpere eller driftsdatabaser til en ny installasjon.

## Opprett et oppsett

Åpne «GuToChat Prøveutgave Oppsett» fra programmenyen. Alternativt kjører du dette på maskinens eget skrivebord, uten sudo:

```bash
/usr/bin/python3 -I /usr/lib/gutochat-preview/setup_ui.py
```

Velg Norsk eller English og Base eller Field. Velg «Installer nytt oppsett» / «Install new setup», kontroller rollen i dialogen og bekreft lokalt. Vent på «Handlingen er fullført» / «The operation is complete». Du må deretter lukke veiviseren selv. Gjenta for den andre rollen bare hvis du ønsker den.

Et eksisterende oppsett skal ikke overskrives med «Installer nytt oppsett». Bruk «Gjenoppta oppsett» etter en kontrollert oppgradering eller reinstallasjon. Se [oppgradering og avinstallasjon](DRIFT_OG_OPPGRADERING.md).

## Åpne og kontroller

Åpne Base eller Field fra programmenyen. Alternativ:

```bash
/usr/bin/python3 -I /usr/lib/gutochat-preview/gui_entry.py base
```

Bytt siste ord til `field` for Field. GUI-en skal kjøres som vanlig bruker. Kontroller Systemstatus og fanen «Oppsett og enheter» / «Setup and devices». Tjenestene og GUI-vinduene er forskjellige: automatisk tjenesteoppstart beviser ikke at et GUI-vindu skal åpnes automatisk.

## Valgfri Meshtastic-radio

Den medfølgende driverkandidaten er for arm64 og Python 3.13. Installer den bare når denne kombinasjonen passer:

```bash
sudo apt-get --no-remove install ./gutochat-driver-r4.deb
```

Den fysiske radioaksepten gjelder én Heltec V3 på Base, med allerede kontrollert 433-MHz-oppsett, og en T433 som motpart. Registrering og valg i GuToChat er ikke firmwareinstallasjon eller automatisk konfigurering av radioens region, kanal, antenne eller effekt. Kontroller dette separat før bruk. Ingen 868-/433-innstillinger skal kopieres mellom ulike bånd uten egen kontroll.

Bruk radioens stabile USB-identitet i radioveiviseren og «Oppsett og enheter». Registrer radioen, velg den, lagre raden, kontroller installasjonen og bruk oppsettet gjennom den bekreftede handlingen som lukker GUI-en. Verifiser deretter mottakskvittering og svar. Ikke la en annen klient overta Base-radioens forbindelse samtidig.

Automatisk X433-tilkobling etter omstart er fortsatt uavklart. Se [kjente begrensninger](VERSJONSNOTATER.md). Flere radioer, Field-lokal radio, Waveshare, SDR/APRS og kartpublisering har ikke fått samme installasjonsaksept i denne kandidaten.

## Databasekontroll

«KONTROLLER» med «Integrity not_run» betyr at programmet mangler et registrert
integritetsresultat. Det er ikke i seg selv bevis på databaseskade. En ekstern
kontroll og programmets egen registrerte kontroll er ulike ting. Under
«Drift og kø» kan du velge «Kjør databasevedlikehold» for en full kontroll.
Vent på resultatet og åpne Systemstatus igjen. «Kjør selvtest» kontrollerer
forbindelser og erstatter ikke denne databasekontrollen.
