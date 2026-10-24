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
