/**
 * Parolele panoului: parametrii, pragul de timp, și ridicarea hashului vechi.
 *
 * Ce se strică pentru operator dacă vreunul dintre testele de aici lipsește:
 * autentificarea panoului e SINGURUL control care apără istoricul derivat a N
 * servere pe o găzduire partajată — fără sandbox systemd, fără SELinux, fără
 * fail2ban al nostru, cu personalul furnizorului având acces la bază. Un
 * parametru Argon2id coborât tăcut, sau un utilizator necunoscut care răspunde
 * în 1 ms, nu produc niciun simptom până în ziua în care produc tot.
 *
 * Acordul cu serverul (`sentinel/web/security.py`) se probează dintr-un test
 * PYTHON — `tests/unit/test_aggregator_auth_parity.py` —, fiindcă acolo se poate
 * pune hashul produs aici în fața verificatorului real al serverului. Aici se
 * probează ce se poate proba din TypeScript.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH, PasswordPolicyError, argon2Load, hashPassword, needsRehash,
  validatePasswordStrength, verifyPassword,
} from "../lib/auth/password";

const PASSWORD = "parola-de-proba-lunga-2026";

test("un hash poartă EXACT parametrii ceruți, iar aceia sunt cei ai serverului", async () => {
  // Parametrii sunt scriși în șirul PHC, deci se pot citi înapoi din ce s-a
  // produs — nu din constantele care i-au produs. Diferența contează: o
  // bibliotecă ce ar ignora tăcut `memorySize` ar trece o comparație de
  // constante și ar pica aici.
  const hash = await hashPassword(PASSWORD);
  assert.match(hash, /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/);
  const [, m, t, p] = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(hash) as RegExpExecArray;
  assert.equal(Number(m), ARGON2_MEMORY_KIB);
  assert.equal(Number(t), ARGON2_TIME_COST);
  assert.equal(Number(p), ARGON2_PARALLELISM);
  // Și valorile chiar sunt cele din `security.py:73-80`. Scrise aici ca literali
  // ca o schimbare la ambele capete deodată să nu treacă neobservată: testul
  // Python cere egalitatea cu serverul, ăsta cere ca nimeni să nu miște tăcut
  // AMBELE surse.
  assert.equal(ARGON2_MEMORY_KIB, 65536);
  assert.equal(ARGON2_TIME_COST, 3);
  assert.equal(ARGON2_PARALLELISM, 2);
});

test("același hash nu se produce de două ori: sarea e aleatoare", async () => {
  // Cu o sare fixă, două conturi cu aceeași parolă au același hash — iar cine
  // citește baza află asta fără să spargă nimic, și un tabel precalculat devine
  // util.
  const seen = new Set<string>();
  for (let i = 0; i < 3; i++) seen.add(await hashPassword(PASSWORD));
  assert.equal(seen.size, 3);
});

test("parola corectă trece, orice altă parolă nu", async () => {
  const hash = await hashPassword(PASSWORD);
  assert.deepEqual(await verifyPassword(hash, PASSWORD), { ok: true, needsRehash: false });
  for (const wrong of [PASSWORD + " ", PASSWORD.toUpperCase(), "altceva-lung-12345", ""]) {
    const result = await verifyPassword(hash, wrong);
    assert.equal(result.ok, false, `parola „${wrong}” a fost acceptată`);
    // Și permisul semaforului se întoarce după FIECARE, inclusiv după parola
    // goală. Aia nu e o intrare exotică: e chiar ce trimite formularul când
    // cineva apasă Enter pe un câmp gol, iar `hash-wasm` o refuză ARUNCÂND, nu
    // întorcând `false` (măsurat — e singura din listă care iese pe ramura de
    // excepție a lui `verifyPassword`). Deci e cea mai ieftină cale din afară
    // spre un permis pierdut: cu `release()` scos din `finally`, o singură cerere
    // anonimă cu parola goală lasă semaforul ocupat pentru totdeauna, iar fiecare
    // autentificare de după ea așteaptă la nesfârșit — panoul inaccesibil până la
    // repornirea procesului, fără nicio eroare nicăieri.
    //
    // Aserțiunea e ÎN buclă, imediat după verificare, nu după ea: cu permisul
    // pierdut, următoarea verificare NU pică, ci așteaptă, iar o aserțiune de
    // după buclă n-ar ajunge niciodată să ruleze. Măsurat: aceeași mutație a
    // oprit suita 300 s fără să tipărească nimic. Un blocaj nu e un test roșu.
    assert.deepEqual(argon2Load(), { running: 0, waiting: 0 },
                     `după parola „${wrong}” permisul semaforului nu s-a întors`);
  }
});

test("un hash stricat e un REFUZ, nu o excepție care dă 500 pe /login", async () => {
  // Un rând umblat, o coloană tăiată, un algoritm vechi: toate arată la fel
  // pentru cel care încearcă să intre, și niciunul n-are voie să scoată din uz
  // pagina de autentificare.
  for (const broken of ["", "nu-e-un-hash", "$argon2id$v=19$m=65536,t=3,p=2$prea$scurt"]) {
    const result = await verifyPassword(broken, PASSWORD);
    assert.deepEqual(result, { ok: false, needsRehash: false }, broken);
    // A doua cale pe care Argon2 iese cu excepție — prima e parola goală, în
    // testul de mai sus. Se cere și aici, în buclă și din același motiv, fiindcă
    // sunt două declanșatoare diferite ale aceluiași defect: unul vine din
    // formular, ăsta vine din rândul stocat, iar o reparație care l-ar acoperi
    // doar pe unul ar arăta verde.
    assert.deepEqual(argon2Load(), { running: 0, waiting: 0 },
                     `hashul „${broken}” a aruncat și permisul nu s-a întors: ` +
                     "următoarea autentificare așteaptă la nesfârșit, iar panoul e " +
                     "inaccesibil până la repornirea procesului");
  }
});

test("un hash cu alți parametri se verifică, dar cere ridicare", async () => {
  // Mecanica prin care o schimbare de cost nu cere nimănui o resetare de parolă.
  // `needsRehash` citește parametrii DIN hash, deci răspunde despre rândul din
  // bază, nu despre configurația de azi.
  assert.equal(needsRehash(`$argon2id$v=19$m=${ARGON2_MEMORY_KIB},t=${ARGON2_TIME_COST},` +
                           `p=${ARGON2_PARALLELISM}$c2FyZQ$aGFzaA`), false);
  assert.equal(needsRehash("$argon2id$v=19$m=16384,t=3,p=2$c2FyZQ$aGFzaA"), true);
  assert.equal(needsRehash("$argon2id$v=19$m=65536,t=1,p=2$c2FyZQ$aGFzaA"), true);
  assert.equal(needsRehash("$argon2id$v=19$m=65536,t=3,p=1$c2FyZQ$aGFzaA"), true);
  // Un algoritm care nu e argon2id — bcrypt, argon2i, orice — nu e „la zi".
  assert.equal(needsRehash("$argon2i$v=19$m=65536,t=3,p=2$c2FyZQ$aGFzaA"), true);
  assert.equal(needsRehash("$2b$12$abcdefghijklmnopqrstuv"), true);
  // Și o formă pe care n-o pot citi: „nu recunosc" nu e „e în regulă".
  assert.equal(needsRehash(""), true);
});

test("lungimea e singura regulă, și are două capete", () => {
  // Fără plafonul de sus, o intrare de câțiva megaocteți e CPU ars în Argon2 la
  // fiecare cerere — o negare de serviciu care nu are nevoie de niciun cont.
  assert.throws(() => validatePasswordStrength("a".repeat(MIN_PASSWORD_LENGTH - 1)),
                PasswordPolicyError);
  assert.throws(() => validatePasswordStrength("a".repeat(MAX_PASSWORD_LENGTH + 1)),
                PasswordPolicyError);
  assert.doesNotThrow(() => validatePasswordStrength("a".repeat(MIN_PASSWORD_LENGTH)));
  assert.doesNotThrow(() => validatePasswordStrength("a".repeat(MAX_PASSWORD_LENGTH)));
  // Fără reguli de compoziție, dinadins — vezi `validate_password_strength` din
  // `security.py`: împing oamenii spre `Password1!` și nu mai sunt recomandate
  // de NIST din 2017.
  assert.doesNotThrow(() => validatePasswordStrength("parola parola parola"));
});

test("o parolă prea scurtă nu se poate hashui nici din greșeală", async () => {
  // Politica se aplică la scriere, nu doar în formular. Un cont creat dintr-un
  // script ocolește formularul.
  await assert.rejects(() => hashPassword("scurta"), PasswordPolicyError);
});

/** Mediana, ca o singură măsurătoare nefericită să nu decidă. */
function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

test("utilizator necunoscut și parolă greșită costă la fel", async () => {
  // PROPRIETATEA CARE SE PIERDE CEL MAI UȘOR ÎNTR-O REWRITE, și de-aia planul o
  // cere explicit: fără hashul-fantomă, un nume care nu există răspunde imediat,
  // iar unul care există costă o verificare Argon2 întreagă. Diferența se vede
  // dintr-un `curl`, iar enumerarea de utilizatori e primul pas al fiecărui atac
  // pe credențiale — pe un panou al cărui singur control e autentificarea.
  //
  // Se MĂSOARĂ, nu se presupune. O aserțiune că „se cheamă verifyPassword și pe
  // ramura cealaltă" ar fi trecut și peste o implementare care întoarce imediat.
  //
  // Măsurătorile se interclasează (necunoscut, cunoscut, necunoscut, …): mașina
  // pe care rulează suita e încărcată neuniform, iar două serii una după alta ar
  // fi măsurat sarcina, nu munca.
  const hash = await hashPassword(PASSWORD);
  // O trecere înainte de măsurare: prima verificare din viața procesului plătește
  // și calculul hashului-fantomă.
  await verifyPassword(hash, "gresit-dar-lung-123");

  const known: number[] = [];
  const unknown: number[] = [];
  for (let i = 0; i < 5; i++) {
    let started = process.hrtime.bigint();
    assert.equal((await verifyPassword(null, "gresit-dar-lung-123")).ok, false);
    unknown.push(Number(process.hrtime.bigint() - started) / 1e6);

    started = process.hrtime.bigint();
    assert.equal((await verifyPassword(hash, "gresit-dar-lung-123")).ok, false);
    known.push(Number(process.hrtime.bigint() - started) / 1e6);
  }

  const withUser = median(known);
  const without = median(unknown);
  // Raportul se ia PE PERECHE, iar mediana se ia peste rapoarte — nu raportul
  // medianelor pe braț. Ce e schimbarea asta, spus exact: o îmbunătățire de
  // statistică DOVEDITĂ PE BANC, nu reparația unei instabilități măsurate.
  // Distincția contează, fiindcă versiunea dinainte a acestui comentariu scria
  // a doua variantă, cu un tabel de constante care nu se mai reproduce.
  //
  // Mecanismul de care se ferește: necunoscutul e ÎNTOTDEAUNA primul din
  // pereche, deci o încetinire care începe la mijlocul ferestrei lasă brațele cu
  // numere diferite de eșantioane scumpe — începută între necunoscutul și
  // cunoscutul perechii a treia, brațul cunoscut are trei (3, 4, 5) iar cel
  // necunoscut doar două (4, 5), și medianele pe braț ajung de-o parte și de
  // alta a ei. Rapoartele pe perechi compară cele două ramuri în ACELAȘI moment,
  // iar o încetinire care strică o singură pereche nu poate muta a treia
  // statistică de ordine din cinci.
  //
  // Dovada e o simulare exhaustivă: toate cele 4×1024 de tipare binare de
  // încetinire peste 10 eșantioane, cu rapoarte de cost 1.5, 2, 2.7 și 4.
  // Estimatorul pe perechi domină pe AMÂNDOUĂ felurile de eroare:
  //
  // | din 4096 de tipare | mediane pe braț | rapoarte pe pereche |
  // |---|---|---|
  // | fals ROȘU (fără oracol)                | 2048 | 848 |
  // | fals VERDE (oracol în fiecare pereche) | 1024 | 424 |
  //
  // Și, mai mult decât numerele: tipare unde NOUL e roșu și vechiul verde — 0;
  // tipare unde NOUL ratează oracolul și vechiul îl prinde — 0. Zero
  // contraexemple, deci o dominare, nu un compromis. Construcția adversarială
  // evidentă (3 perechi din 5 încetinite asimetric, doar pe latura necunoscută)
  // le face roșii pe amândouă, deci nu e o cale de a strecura ceva pe lângă cel
  // nou. Punctul orb pe 1 și pe 2 perechi din 5 e IDENTIC la amândoi — nu e o
  // regresie. Intrările degenerate eșuează în siguranță.
  //
  // Treapta de cost pe care mecanismul o presupune EXISTĂ pe mașina de
  // dezvoltare, reprodusă independent — `17: 131.6 ms → 18: 220.0 → 19: 379.3 →
  // … → 30: 384.4`, cu `rss` plat la 148 MiB și `external` plat la 70 MiB — dar
  // e o proprietate a MAȘINII, nu a codului. Cauza scrisă aici înainte („după
  // ~20 de calcule, fiindcă memoria celor 64 MiB e dată înapoi sistemului și
  // plătită din nou la fiecare apel") e FALSĂ, prin trei controale:
  //
  //   * nu ține de numărul de apeluri: cu `m=8192` (8 MiB per apel) treapta cade
  //     la iterația 181, la 2.87 s scurse, față de iterația 18 la ~2.5 s cu
  //     `m=65536` — același timp, de zece ori mai multe apeluri. Invariantul e
  //     ~2.5–2.9 s de muncă susținută, nu „~20 de calcule";
  //   * nu e memorie replătită per apel: cu 400 ms pauză între apeluri, deci cu
  //     alocare per apel identică, nu apare nicio treaptă în 30 de iterații /
  //     16.7 s, de două ori. Ce se vindecă stând degeaba nu e alocare;
  //   * nu e timp de procesor generic: șase secunde de buclă JS pură înainte de
  //     fereastră lasă 12 eșantioane, toate ~140 ms, fără treaptă.
  //
  // Nici stabilă nu e: cinci rulări au dat 2 permanentă, 1 tranzitorie, 2
  // absentă; mai târziu a dispărut cu totul, iar linia de bază s-a mutat de la
  // 138 la 133 ms. Semnătura — ~2.7× sub muncă susținută intensivă în bandă de
  // memorie, vindecabilă prin repaus — e de tranziție de putere/termică pe un
  // procesor hibrid de laptop, nu un efect de memorie. Deci nu se așteaptă în
  // aceeași formă pe găzduirea agregatorului, unde n-a măsurat-o nimeni.
  //
  // De-aia dovada e simularea și nu un banc. Bancul dinainte — „K verificări în
  // plus imediat după încălzire mută treapta prin fereastră; K=4 → 10 roșii din
  // 10 pe estimatorul vechi" — NU se reproduce: șaisprezece rulări la K=4 dau 0
  // roșii din 16. Nu fiindcă n-ar fi fost măsurat, ci fiindcă mașina a ieșit din
  // starea aia. Un tabel de praguri dependente de starea mașinii n-are ce căuta
  // într-un docstring ca listă de constante măsurate.
  //
  // Și fâlfâitul de ~26% de la care a plecat schimbarea N-A FOST REPRODUS de
  // nimeni, cu niciun estimator. Treapta chiar cade în fereastra de măsurare —
  // 12 din 12 rulări in situ au arătat-o, mereu pe perechea 5, mereu pe ultimul
  // eșantion — dar ambii estimatori rămân verzi: un singur eșantion stricat la
  // capăt nu poate muta a treia statistică de ordine din cinci. Estimatorul
  // vechi n-a fost văzut NICIODATĂ roșu in situ, iar controlul de atunci n-avea
  // putere să distingă 26% de zero: la o rată reală de 26%, șase rulări curate
  // la rând se întâmplă în `0.74^6 = 16.4%` din cazuri, cam o dată din șase.
  const ratios = unknown.map((u, i) => u / known[i]);
  const ratio = median(ratios);
  // Măsurătoarea trebuie să aibă ce măsura: dacă o verificare durează sub 20 ms,
  // ori parametrii au fost coborâți, ori nu s-a făcut nicio verificare — și
  // atunci raportul de mai jos n-ar dovedi nimic.
  assert.ok(withUser > 20,
            `o verificare Argon2id a durat ${withUser.toFixed(1)} ms; la m=65536,t=3 ` +
            "nu se poate, deci ori parametrii, ori măsurătoarea sunt greșite");
  // Banda: ±20–25%, nu ±100%.
  //
  // Cea dinainte (`0.5×`–`2×`) era de patru ori mai largă decât proprietatea, și
  // se vede la ce trecea prin ea. Măsurat, cu fantoma slăbită dinadins:
  //
  // | fantoma la | necunoscut / existent | banda veche | banda asta |
  // |---|---|---|---|
  // | fără fantomă  | 0.0 / 133.5 ms | roșu  | roșu |
  // | `m=16384` (4× mai ieftină)   | 30.2 / 135.1 | roșu  | roșu |
  // | `m=49152` (25% mai ieftină)  | 101 / 135    | VERDE | roșu |
  // | `t=2` (33% mai ieftină)      |  90 / 135    | VERDE | roșu |
  //
  // Cele trei fantome slăbite au fost măsurate din nou după trecerea la rapoarte
  // pe pereche, fiindcă o statistică schimbată e o probă schimbată: fără fantomă
  // 0.00, `m=16384` 0.23, `m=49152` 0.73 — toate roșii, și toate cu cele cinci
  // perechi la fel (`0.73, 0.73, 0.73, 0.73, 0.72`). Un oracol adevărat e în
  // FIECARE pereche; de-aia mediana pe perechi îl prinde mai bine decât zgomotul.
  // Rândul cu `t=2`, marcat aici o vreme drept preluat nemăsurat, a fost măsurat
  // la verificare: `0.69–0.70`, roșu la amândoi estimatorii. Tabelul e întreg.
  //
  // Un oracol de enumerare de ~45 ms în absolut e vizibil dintr-un `curl` la fel
  // de bine ca unul de 135 ms; banda veche îl lăsa să treacă. Marginile de aici
  // sunt măsurate, nu alese: rapoartele pe pereche stau în 0.97–1.04 peste rulări
  // repetate, deci 0.8–1.25 lasă loc de câteva ori zgomotul observat.
  //
  // Banda a fost raportată o dată ca fâlfâind — „utilizator necunoscut: 147.5 ms,
  // utilizator existent: 280.4 ms", adică un raport de ~0.53 fără ca ramurile să
  // difere cu ceva. Rata de atunci, ~26%, n-a mai fost reprodusă de nimeni, nici
  // cu estimatorul vechi (vezi mai sus), deci ce s-a schimbat NU e reparația unui
  // fâlfâit măsurat, e un estimator dovedit mai robust. Ce rămâne valabil e de ce
  // s-a schimbat ESTIMATORUL și nu banda: o bandă lărgită înapoi la `0.5×–2.0×`
  // ar fi făcut testul verde și ar fi lăsat să treacă un oracol de ~45 ms, adică
  // tocmai ce păzește testul.
  assert.ok(ratio > 0.8 && ratio < 1.25,
            `raportul median necunoscut/existent e ${ratio.toFixed(2)} ` +
            `(pe perechi: ${ratios.map((r) => r.toFixed(2)).join(", ")}; ` +
            `mediane pe braț: ${without.toFixed(1)} / ${withUser.toFixed(1)} ms). ` +
            "Diferența spune dacă un nume există.");
});
