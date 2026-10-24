# GuToChat – norsk

GuToChat har rollene Base og Field. Grunnprogrammet kan installeres og åpnes
uten radio. Radiomeldinger krever en valgt og konfigurert adapter.

Kandidat 18 (`2.5.0~preview20261024.18docs1`, driver 4) har bestått en
oppgraderingsprøve på Raspberry Pi 5, Debian 13 arm64 og Python 3.13. Brukeren
bekreftet at vinduene åpnes, mottakeren kvitterer og svaret kommer tilbake via
Meshtastic-prøveruten på 433 MHz. Dette er en avgrenset eksperimentell prøveutgave.
Last ned [prøveutgaven og tilhørende kilder](https://github.com/gunnartoftegaard/GuToChat/releases/tag/v2.5.0-preview18).

- [Installasjon](docs/no/INSTALLASJON.md)
- [Drift og oppgradering](docs/no/DRIFT_OG_OPPGRADERING.md)
- [Feilsøking](docs/no/FEILSOKING.md)
- [Versjonsnotater og prøvd omfang](docs/no/VERSJONSNOTATER.md)
- [Bygge fra kilde](BYGGING_NO.md)
- [Lisens og kildeleveranse](LISENS_NO.md)
- [Utgivelsesvedlegg og kontrollsummer](RELEASE_ASSETS.json)
- [English](README.md)

`src/` er den eksakte kildekopien for den prøvde pakken. Manifestet og pakkens
dokumentasjon beholdes slik de ble levert; veiledningene over beskriver den
senere aksepten. Kilde-/byggevedlegget inneholder begge pakketrærne og tilhørende
oppstrømskilder, wheels, merknader og byggegrunnlag.

Prosjekteide filer beholder MIT-tillatelsene. Det kombinerte programmet med
Meshtastic leveres under GPLv3-only-vilkår; hele leveransen er ikke MIT-only.
Se LISENS_NO.md og komponentenes merknader.

Alle 35 planspor beholdes; prøveutgaven gjennomfører ikke hele utviklingsplanen.
Kontakt: post@gutochat.no. [Nettside](https://www.gutochat.no/no/).
[GitHub-lager](https://github.com/gunnartoftegaard/GuToChat).
PayPal/GitHub Sponsors er planlagt; betalingsadresse er ikke lagt inn.
