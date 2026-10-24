# Kandidat 18 – oppgradering og meldingsprøve bestått

Program `2.5.0~preview20261024.18docs1`; uendret valgfri driver
`2.7.9~gutochat20261024.4`. Utgivelsen er merket som en eksperimentell prøveutgave.

## Endringer

- Tidligere rettelser for Base-oppstart, ugyldig lengdegrad og tidlige
  mottakerkvitteringer er beholdt.
- Kandidat17 serialiserer kontroll av Field-synkmarkør og lagring av siden.
- Kandidat18 legger til manglende nullable `ingested_epoch` før en indeks for
  eldre posisjonshistorikk opprettes. Initialiseringen serialiseres. Gamle verdier
  beholdes uten oppdiktede historiske innlesingstidspunkter.
- Norske og engelske veiledninger følger pakken. Driver4 har flere merknader;
  selve driverbibliotekene er uendret.

## Aksept 24. oktober 2026

Raspberry Pi5, Debian13 arm64, Python3.13.5:848 installerte pakkefiler kontrollert,
pakkebehandlerens kontroll uten feil. Innstillinger og begge databaser er bevart.
Begge kjernetjenester og X433-adapteren svarer. Brukeren bekrefter at begge GUI-er
åpnes, og at test-Base mottar mottakerkvittering og svar fra T433. Språkinnstillingene
NB/EN er beholdt. Dette var oppgradering, ikke nyinstallasjon av kandidat18,
fysisk Field-synkronisering eller en ny maskinomstartsprøve.

Isolerte prøver på Windows/Pi:18 installasjonskontrakter,10 ACK-tilfeller,5
lagertester,3 prøver av eldre posisjonsdatabaser,8 GUI/kjerne-tester,10 mesh-/
prosessavbruddstester og5 databasekonkurranse-/gjenopprettingsprøver. Dette er
avgrensede kontroller, ikke full sikkerhets- eller belastningsdekning. Native
biblioteker er ikke kompilert på nytt; generell installasjonsgjenoppretting er
ikke godkjent.

## Kjente begrensninger

- Ubetjent X433-gjentilkobling etter omstart er uavklart; ekstra prøve er utsatt.
- Full installasjonsgjenoppretting av pakker, eierskap, tjenester og radiooppsett
  er ikke akseptert. Syntetisk databasegjenoppretting består, men er snevrere.
- Eldre APRS-iGate v1/v2-kømigrering har en urettet `evaluated_epoch`-indeksfeil.
  APRS-oppgraderinger er utenfor prøveutgavens støttede installasjonsomfang.
- Valgfrie, ukonfigurerte APRS-moduler kan vises med degradert/ukjent status.
- Fjernstatus fra Base kan vises PÅ/ON med utdaterte detaljer på drifts-Field.
- Noen feildetaljer er engelske i norsk GUI; gamle kartrader kan vises etter
  ugyldige kartkoordinater.
- Andre radiokombinasjoner,868,Waveshare,RTL-SDR/APRS og kartpublisering har ikke
  tilsvarende installasjonsaksept her. Driveren krever arm64 og Python3.13.
  Andre Pi-modeller og32-bit-systemer er ikke akseptert gjennom prøven.

Driftsmaskinene er ikke oppgradert. Alle35 planspor beholdes; prøveutgaven
fullfører ikke utviklingsplanen. Øvrige store kontroll-/kodeområder er ikke
fremstilt som uttømmende revidert.
