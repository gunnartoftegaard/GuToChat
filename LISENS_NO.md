# Lisens og tilhørende kildeleveranse

Prosjekteid GuToChat/GuToMap-materiale beholder MIT-lisensen i LICENSE og
opprinnelige merknader. Avhengigheter beholder komponentenes egne lisenser.

Meshtastic Python2.7.9 er GPL-3.0-only og importeres i radiokomponentenes prosess.
Det kombinerte programmet med Meshtastic tilbys under GPLv3-only-vilkår, mens
MIT-tillatelsene og alle oppstrømsmerknader beholdes. Separate DEB-filer gjør ikke
det importerte biblioteket til et uavhengig program. Hele leveransen beskrives
ikke som MIT-only. Tredjepartskode gis ikke ny lisens.

Full GPL-tekst: [GPLv3](LICENSES/GPL-3.0.txt). Behold prosjektets MIT-merknad og
komponentenes merknader ved kopiering og distribusjon. Kildetilgang er del av
utgivelsen, ikke en valgfri betalingstjeneste.

Legg tilhørende kilde-/bygge-ZIP ved BEGGE binærpakkene, med kontrollsummer og
tilgjengelig lenke fra samme utgivelse. Binærpakkene skal ikke publiseres alene.
RELEASE_ASSETS.json identifiserer filene. Kildevedlegget inneholder eksakte prosjekt-
og drivertrær,15 oppstrømskildearkiver og wheels, tilhørende protokollskjemaer,
Google Protobuf/libyaml-kilder, oppstrømsoppskrifter og opprinnelsesinformasjon.
Driver4 installerer tilleggsmerknader for libyaml,utf8_range og protokollene.

Verktøyene rekonstruerer DEB-pakkene; opprinnelige wheels forklarer bibliotekbytene.
Native biblioteker er ikke kompilert fra kilde i denne prøven. Dette er ikke en
erklæring om full juridisk klarering eller uttømmende transitive lisensmerknader.

Grunnlag: [GPLv3 avsnitt1,5,6](https://www.gnu.org/licenses/gpl.en.html),
[GNU FAQ om kombinerte moduler](https://www.gnu.org/licenses/gpl-faq.en.html#GPLModuleLicense).
