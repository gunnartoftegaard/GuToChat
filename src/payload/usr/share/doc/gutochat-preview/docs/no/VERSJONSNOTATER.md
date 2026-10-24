# Kandidat 18 – klargjort, ikke installert

Program: 2.5.0~preview20261024.18docs1. Uendret driver4.
Posisjonshistorikk fra eldre utgaver får den manglende nullable ingested_epoch-
kolonnen før indeksoppretting. Oppstartene serialiseres under migreringen.
Gamle verdier bevares; tidligere punkter får ingen oppdiktet innlesingstid.
Tre isolerte migrasjons-/databevaringsprøver på begge roller består lokalt og
på Pi. Kandidat17 er fortsatt den installerte, GUI-aksepterte testutgaven.

Norsk/engelsk GitHub-dokumentasjon er nå også inkludert i program­pakken.
Binærpakkene, kildegrunnlaget og den lokale GitHub-kladden er versjonssamordnet.
Ingen ny installasjons-, fysisk radio-/synk- eller omstartsprøve påstås.

Eldre APRS-iGate-køer med v1/v2-tabeller har et separat bekreftet migrasjonsproblem
med evaluated_epoch-indeksen. Denne modulen har ikke samme installasjonsstøtte
som grunnprogrammet/den ene testede 433-adapteren; APRS-oppgradering godkjennes
ikke i denne kandidaten. Ingen driftsdatabase er undersøkt eller endret av prøven.
Åpne kodegjennomgangs- og driftskrav beholdes. Offentlig publisering avventer.


## Kandidat 17 / Candidate 17

# Versjonsnotater – kandidat 17

Program: `2.5.0~preview20261024.17sync1`. Valgfri driver: `2.7.9~gutochat20261024.4`.
Dette er en kladd for en avgrenset prøveutgave. Ingen offentlig utgivelse er opprettet.

- Kandidat 15 rettet behandling av ikke-endelige og svært store lengdegrader.
- Kandidat 16 rettet tap av svært tidlige mottakskvitteringer i begge roller.
- Kandidat 17 serialiserer Field sin cursor-kontroll og lagring av meldingssynkronisering.
- Driver 4 inneholder de supplerende lisensvedleggene. Bibliotekene er uendret fra driver 3.
- Den tidligere Base-oppstartsrettelsen er bevart; Base og Field beholder separate lagringsvarianter.

Test-Pi: Raspberry Pi 5, Debian 13 aarch64, Python 3.13.5. Kandidat 17 er installert;
839 pakkefiler og bevaring av innstillinger/data er kontrollert. Begge GUI-er åpnes,
Base på norsk og Field på engelsk, og begge viser database OK etter full kontroll.
18 installasjonskontrakter, fem lagringsprøver og ti kvitteringskontroller består
lokalt og isolert på Pi. Kvittering/svar med X433/T433 ble fysisk bekreftet i kandidat 16.
Det er ikke en påstått ny radiomeldings-, fysisk Field-synk- eller omstartsprøve i 17.

## Kjente begrensninger

- Ubetjent X433-tilkobling etter omstart er uavklart. Ny omstartsprøve er utsatt etter brukerens ønske.
- Periodisk SQLite-konkurranse, full restart/replay og operativ gjenoppretting er ikke sluttgodkjent.
- Valgfrie testmoduler som ikke er konfigurert kan vise DEGRADED/ukjent i stedet for AV/ikke konfigurert.
- På drifts-Field kom Base-statusene frem som ON etter oppdatering, men ble fortsatt merket utdaterte. Årsaken er ikke fastslått.
- Noen feildetaljer er på engelsk i norsk GUI; karttabellen kan beholde gamle rader etter ugyldig viewport.
- Flere radiokombinasjoner, 868, Waveshare, SDR/APRS og kartpublisering har ikke samme akseptgrunnlag i denne installasjonspakken.

De kjørende driftsmaskinene er egne installasjoner. Ny funksjonalitet på test-Pi
innebærer ikke at driftsmaskinene er oppgradert. Alle 35 planspor og den bevarte
utviklingshistorien videreføres; prøveutgaven gjør ikke hele utviklingsplanen ferdig.
