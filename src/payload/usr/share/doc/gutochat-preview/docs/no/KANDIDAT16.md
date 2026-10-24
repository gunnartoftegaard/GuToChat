Historisk kandidatnotat; gjeldende status står i README og versjonsnotatene.

# Kandidat 16 – kvitteringer og samlet kildegrunnlag

Intern testkandidat, ikke publisert. Program 2.5.0~preview20261024.16ack1;
valgfri driver 2.7.9~gutochat20261024.4.

Rettet en bekreftet tidsfeil i begge rollers send_text: en kvittering som kom
under lagring av meldingen kunne bli behandlet før venteposten fantes og dermed
gå tapt. Pakke-ID gjøres nå tilgjengelig for callbacken først etter at venteposten
er lagret. Tidlige svar beholdes under den eksisterende låsen.

Ti isolerte kontroller består lokalt og på test-Pi med Python 3.13.5. Fire
feiltilfeller ble først gjenskapt i kandidat 15. Dette er ikke en ny fysisk
radioprøve eller bevis for årsaken til tidligere USB-feil.

Driverbibliotekene er byteidentiske med driver 3; bare versjon og dokumentasjon
endres. De tre manglende lisensvedleggene er nå med i selve driverpakken.
Kildepakken samler de 15 kildearkivene, hjulfilene, protokolldefinisjonene,
Google Protobuf-kildene, libyaml-kildene og byggegrunnlaget.

Kandidat 15s kart- og hjelpeaksept beholdes som historisk bevis. Kandidat 16 er
ikke installert eller fysisk aksepttestet. Ingen ny omstartsprøve er utført;
usikker X433-tilkobling etter omstart og øvrige åpne driftsprøver består.
Full gjenstående kodegjennomgang og endelig publiseringsbeslutning er fortsatt åpne.
Alle 35 planspor og den tidligere Base-oppstartsrettelsen beholdes.
