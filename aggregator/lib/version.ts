/**
 * Versiunea agregatorului, ca s-o arate panoul — și de unde vine.
 *
 * O SINGURĂ sursă: `version` din `package.json`. Un șir scris în `panel-page.ts` ar arăta
 * `0.1.0` la nesfârșit în timp ce versiunea reală se mută; importul de aici e rezolvat la
 * build (`resolveJsonModule`), deci nu există fișier de citit la rulare pe găzduire și nu
 * există un `readFileSync` care să cadă pe o cale greșită. `tests/version.test.ts` compară
 * ce randează pagina cu `package.json` citit separat.
 *
 * E versiunea AGREGATORULUI, nu a vreunei instanțe Sentinel: agregatorul afișează date de la
 * mai multe instanțe deodată, iar o versiune de instanță n-ar avea niciun loc din care să vină
 * (nici beacon-ul, nici fluxurile nu o poartă). De-aia eticheta spune „Agregator", nu „Sentinel".
 */

import pkg from "../package.json";

export const VERSION: string = pkg.version;

export type ReleaseStage = "beta" | "stable" | "unknown";

/**
 * `beta` sub 1.0, `stable` de la 1.0, `unknown` când șirul nu e o versiune.
 *
 * Aceeași regulă ca `release_stage` din `sentinel/web/jinja.py` (`tests/unit/test_version_label.py`
 * le dă ambelor aceleași cazuri): „beta" iese din cifră, nu dintr-un steag, ca să dispară singur
 * în ziua în care versiunea devine 1.0.0. O versiune pe care n-o putem citi e „necunoscută", NU
 * „beta" — „0.0.0+unknown" e sub 1.0 doar tehnic. Un sufix `-rc1` o face tot `beta`: `1.0.0-rc1`
 * e, prin definiția semver, ÎNAINTE de 1.0.0.
 */
export function releaseStage(version: unknown): ReleaseStage {
  if (typeof version !== "string") return "unknown";
  const m = /^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.exec(version);
  if (m === null || version.endsWith("+unknown")) return "unknown";
  return Number(m[1]) < 1 || m[4] !== undefined ? "beta" : "stable";
}
