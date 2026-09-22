/**
 * „Pe care server mă uit?" — și de ce răspunsul nu poate fi doar o culoare.
 *
 * Tabelul de servere din rezumat marchează rândul ales. Până pe 22 septembrie
 * 2026 îl marca EXCLUSIV cu `background: var(--bg-hover)`, măsurat 1,047:1 față
 * de fundalul paginii: se vede pe un ecran bun dacă știi deja pe care rând să
 * te uiți — adică exact în situația în care n-ai nevoie de marcaj — și nu se
 * vede deloc pe un telefon în lumină.
 *
 * Reparația are două jumătăți, și amândouă se pot pierde separat:
 *
 *   * o dungă de 3px la marginea rândului, care e o FORMĂ, nu un ton. Aia stă
 *     în `public/panel.css` și o păzește
 *     `tests/unit/test_design_system.py::test_the_selected_row_is_marked_by_more_than_a_tint`;
 *   * `aria-current` în marcaj, fiindcă o dungă colorată nu spune nimic unui
 *     cititor de ecran. Aia stă AICI, în `lib/panel-page.ts`, și de-aia testul
 *     ăsta e în suita agregatorului și nu în cea Python: agregatorul se
 *     livrează separat, iar un marcaj care se strică între două livrări nu
 *     trebuie să aștepte cealaltă suită ca să se afle.
 *
 * Regula din capul foii de stil e că nicio culoare nu e singurul semn. Rândul
 * ăsta a fost, un an, excepția pe care n-o observase nimeni.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { summaryPage } from "../lib/panel-page";

const SUMAR = {
  overview: {
    attackers: { now: 0, before: 0 }, detections: { now: 0, before: 0 },
    events: { now: 0, before: 0 }, incidentsOpen: 0, incidentsSevere: 0,
    findingsOpen: 0, blocksActive: 0, bySeverity: [],
  },
  series: [], rankings: { attackers: [], rules: [], sources: [] },
  activity: [], truncated: [],
};

function randeaza(selected: string | null): string {
  return summaryPage({
    username: "operator", csrfToken: "x",
    instances: [
      { instanceId: "prod-a", label: "A", role: "owner", enabled: true,
        lastBatchAt: null },
      { instanceId: "prod-b", label: "B", role: "owner", enabled: true,
        lastBatchAt: null },
    ],
    selected, active: "/panel", arrivals: new Map(),
    incidents: [], sumar: SUMAR,
  } as never);
}

/** Rândurile `<tr ...>` din marcaj, cu atributele lor. */
function randuri(html: string): string[] {
  return html.match(/<tr[^>]*>/g) ?? [];
}

test("rândul ales SPUNE că e ales, nu doar îl arată", () => {
  const html = randeaza("prod-b");
  const alese = randuri(html).filter((r) => r.includes('class="aici"'));
  assert.equal(alese.length, 1,
               `${alese.length} rânduri marcate ca ales: ${alese}`);
  assert.match(alese[0], /aria-current=/,
               "rândul ales n-are `aria-current`: pentru un cititor de ecran " +
               "e un rând ca oricare altul, iar dunga colorată nu-i spune nimic");
  // `true`, nu `page`: rândul nu e o legătură către pagina curentă, e
  // elementul ales din setul afișat. `page` e pentru navigație.
  assert.match(alese[0], /aria-current="true"/,
               "valoarea lui `aria-current` nu e cea pentru «elementul ales»");
});

test("exact UN rând e marcat, și e cel cerut", () => {
  // Eșecul pe care îl previne: marcajul se pune pe fiecare rând, sau pe niciunul.
  // Amândouă arată ca un tabel care funcționează, iar al doilea e chiar starea
  // de dinainte văzută printr-un cititor de ecran.
  const html = randeaza("prod-a");
  const toate = randuri(html);
  assert.ok(toate.length >= 2, `doar ${toate.length} rânduri randate`);
  const marcate = toate.filter((r) => r.includes("aria-current"));
  assert.equal(marcate.length, 1, `${marcate.length} rânduri cu aria-current`);

  // Și e rândul lui prod-a, nu al altcuiva: se taie bucata de HTML de la
  // rândul marcat până la următorul `<tr`, și acolo trebuie să stea eticheta.
  const de_la = html.indexOf(marcate[0]);
  const pana_la = html.indexOf("<tr", de_la + 1);
  const rand = html.slice(de_la, pana_la === -1 ? undefined : pana_la);
  assert.match(rand, /prod-a/, "rândul marcat nu e cel selectat");
  assert.doesNotMatch(rand, /prod-b/, "marcajul a prins două rânduri deodată");
});

test("fără niciun server ales, niciun rând nu pretinde că e cel curent", () => {
  // Starea e reală: un cont proaspăt fără drepturi are `selected === null`.
  // Un `aria-current` rămas lipit pe primul rând ar fi o afirmație falsă
  // spusă cu voce tare, ceea ce e mai rău decât tăcerea.
  const html = randeaza(null);
  assert.equal(randuri(html).filter((r) => r.includes("aria-current")).length, 0);
});

test("clasa și atributul pleacă împreună, nu unul fără altul", () => {
  // Cele două jumătăți ale marcajului se scriu în aceeași expresie tocmai ca
  // să nu se poată despărți. Dacă cineva le desparte, una dintre ele se pierde
  // tăcut: clasa fără atribut e marcajul vechi, doar vizual; atributul fără
  // clasă e un rând anunțat ca ales și desenat ca oricare altul.
  const html = randeaza("prod-b");
  for (const rand of randuri(html)) {
    assert.equal(rand.includes('class="aici"'), rand.includes("aria-current"),
                 `rândul are doar una dintre cele două jumătăți: ${rand}`);
  }
});
