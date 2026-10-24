# Feilsøking

## Ingen passorddialog

Kjør veiviseren som vanlig bruker i Terminal på maskinens eget skrivebord. Administratorbekreftelse fra en fjernstartet GUI ble tidligere observert å feile. Et manglende eller avbrutt passordvindu betyr ikke at operasjonen er fullført. Ikke send passord til prosjektet og ikke deaktiver administratorbekreftelsen som løsning.

## «Unsupported file»

Kontroller nøyaktig filnavn, mappe og at pakken faktisk finnes. Bruk hele stien eller `./filnavn.deb` fra riktig mappe. Ikke lim forklarende tekst inn som del av kommandoen. En tidligere prøve brukte et kortere filnavn, men dette er ikke bevis for at enhver slik feil har samme årsak.

## USB-enheten mangler

Strøm på radioen beviser ikke USB-dataforbindelse. Kontroller USB-datakabel, port og registrert stabil USB-identitet. Bytt bare én del om gangen. Kontroller radioens firmware og faktiske bånd separat; ikke flash eller endre bånd automatisk for å løse en USB-feil. Generiske serienumre kan være like på flere enheter.

## Radioen er aktiv som tjeneste, men ingen meldinger kommer

Kontroller tilkoblingsstatus, kø og mottakskvittering. Unngå samtidig klienttilkobling til selve Base-radioen. Gjentatte sendinger uten kvittering skal undersøkes før flere testmeldinger legges i kø. Meldingsaksept krever både kvittering og et svar tilbake.

Ved én omstart av test-Pi kom X433 ikke automatisk tilbake før et knappetrykk. Strømsparing ble lest som avslått og rollen som CLIENT. Årsaken er uavklart; ikke presenter «slå av dvale» som en bekreftet løsning. Videre omstartsprøver er utsatt etter brukerens valg.

## «Lokal database: KONTROLLER»

Les detaljteksten. «not_run» er ikke det samme som påvist korrupsjon. Ved en faktisk «database disk image is malformed»-feil: unngå vedlikehold eller overskriving før data er sikret og filene som berøres er avklart. En tidligere kartdatabasehendelse og dagens kjernedatabasekontroll er forskjellige bevis.

Ved feilrapport: oppgi versjon, operativsystem, rolle, maskinvare, hva du gjorde og nøyaktig feiltekst. Fjern meldingsinnhold, presise private posisjoner, databaser, nøkler og passord fra offentlige vedlegg. Kontakt: post@gutochat.no. Nettside: https://www.gutochat.no/no/.
