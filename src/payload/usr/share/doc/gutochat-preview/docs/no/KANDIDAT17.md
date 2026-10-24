Historisk kandidatnotat; gjeldende status står i README og versjonsnotatene.

# Kandidat 17 – samtidig Field-synkronisering

Program: 2.5.0~preview20261024.17sync1. Uendret driver: 2.7.9~gutochat20261024.4.
Intern testkandidat; ikke publisert eller installert ennå.

Field reserverer nå SQLite-skriving før den kontrollerer startpunktet for en
meldingssynkroniseringsside. Dermed kan ikke to samtidige oppdateringer begge
godta samme gamle startpunkt og flytte synkroniseringspunktet bakover.
Bare ett programuttrykk er lagt til i Field/message_store.py; AST uten denne
tilføyelsen er identisk med kandidat 16. Base-kode og driver er uendret.

Fem isolerte lagringsprøver dekker duplikater, innholdskonflikt, foreldreløs
duplikatmarkør, feil under lagring, synkroniseringsrollback og to samtidige
oppdateringer. Før rettelsen består fire prøver og samtidighetsprøven feiler;
etter består alle fem, både lokalt og på Pi/Python 3.13.5/SQLite 3.46.1.
Dette er syntetiske databaseprøver, ikke en komplett feltprøve eller lasttest.

Den fysisk aksepterte kandidaten er fortsatt 16: begge GUI-er åpner, Base viser
mottakerkvittering og T433-svaret kommer inn via X433. Bevisene er versjonsbundet.
Base-oppstartsrettelsen, kvitteringsrettelsen, kildegrunnlag, lisensvedlegg og
alle 35 planspor beholdes. Ingen ny omstartsprøve er utført. Øvrig kodegjennomgang,
periodisk SQLite-konkurranse, full replay/gjenoppretting og endelig publisering
er fortsatt åpne; denne ene samtidighetsprøven lukker ikke disse kravene.

Se docs/no/KANDIDAT17.md og medfølgende source_supplement. Ingen driftsmaskin
er endret. Nettsted og GitHub er ikke oppdatert.
