/**
 * Vârful de memorie al unei rafale pe `/login`, MĂSURAT.
 *
 * Fișier separat dinadins: `node --test` rulează fiecare fișier în alt proces,
 * iar aici se compară `rss`-ul procesului înainte și după o rafală. Amestecate
 * cu celelalte probe de parolă, măsurătoarea ar porni de la un `rss` deja urcat
 * de hashurile lor și ar putea trece verde din întâmplare.
 *
 * ## Ce se strică pentru operator dacă probele astea lipsesc
 *
 * Argon2id la `m=65536` alocă 64 MiB per verificare CONCURENTĂ. Pe găzduirea
 * partajată același proces Node servește și `/api/sentinel/sync`, deci dacă
 * verificările se pot suprapune, o rafală de 16 POST-uri pe `/login` — cereri
 * care nu au nevoie de niciun cont — duce `rss` peste 1 GiB (măsurat) și, dacă
 * planul are plafon, omoară procesul. Ce se oprește atunci nu e autentificarea:
 * e INGESTIA arhivei de dovezi a tuturor instanțelor, adică singurul loc în care
 * istoricul de securitate supraviețuiește unui atacator cu root pe gazdă.
 *
 * Se măsoară memoria, nu forma codului: un semafor scris corect și ocolit de un
 * al doilea drum spre Argon2 arată la fel de bine la citire.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MAX_CONCURRENT_ARGON2, MAX_QUEUED_ARGON2, PasswordBusyError, argon2Load,
  hashPassword, verifyPassword,
} from "../lib/auth/password";

const PASSWORD = "parola-de-proba-lunga-2026";
const MIB = 1024 * 1024;

/** Cât alocă o singură verificare. Din `ARGON2_MEMORY_KIB`, scris ca cifră ca
 *  pragurile de mai jos să se poată citi în „câte verificări încap". */
const PER_VERIFICATION_MIB = 64;

test("o rafală de verificări NU ridică memoria proporțional cu ea", async () => {
  // Măsurat fără semafor, pe Node 24, chiar cu parametrii livrați: 8 verificări
  // simultane costă 1071 ms și duc `rss` de la 130 la 578 MiB; 16 costă 2203 ms
  // și 1091 MiB. Cu semaforul, aceleași 16 costă 2158 ms — deci concurența nu
  // cumpăra debit — și lasă `rss` neschimbat.
  const burst = 8;
  const hash = await hashPassword(PASSWORD);
  // O trecere înainte de măsurare: prima verificare din viața procesului
  // plătește și calculul hashului-fantomă, adică încă o alocare de 64 MiB.
  await verifyPassword(hash, PASSWORD);

  const before = process.memoryUsage.rss();
  const started = process.hrtime.bigint();
  const verdicts = await Promise.all(
    Array.from({ length: burst }, () => verifyPassword(hash, PASSWORD)));
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  const grewMiB = (process.memoryUsage.rss() - before) / MIB;

  // Întâi: măsurătoarea are ce măsura. O implementare care ar întoarce un
  // verdict fără să calculeze nimic n-ar aloca nici ea memorie, deci ar trece
  // pragul de mai jos fără să dovedească nimic.
  for (const verdict of verdicts) {
    assert.deepEqual(verdict, { ok: true, needsRehash: false });
  }
  assert.ok(ms > burst * 20,
            `${burst} verificări au durat ${ms.toFixed(0)} ms; la m=65536,t=3 nu ` +
            "se poate, deci nu s-a calculat nimic și măsurătoarea de memorie de " +
            "mai jos nu spune nimic");

  // Pragul e la două verificări, între cele două măsurători: cu semafor
  // creșterea e ~0 MiB, fără el ar fi ~8 × 64 = 512 MiB.
  assert.ok(grewMiB < 2 * PER_VERIFICATION_MIB,
            `o rafală de ${burst} verificări a crescut rss cu ${grewMiB.toFixed(0)} ` +
            `MiB (prag: ${2 * PER_VERIFICATION_MIB}). Memoria crește cu ` +
            "concurența, deci verificările se suprapun — o rafală pe /login " +
            "poate omorî procesul care ingerează arhiva de dovezi");

  // Și nimic nu rămâne agățat: un permis pierdut ar bloca autentificarea până
  // la repornirea procesului, ceea ce e o pană mai lungă decât cea evitată.
  assert.deepEqual(argon2Load(), { running: 0, waiting: 0 });
});

test("o rafală de HASHURI ridică memoria la fel de puțin", async () => {
  // AL DOILEA DRUM spre Argon2, măsurat la fel ca primul. Docstring-ul lui
  // `password.ts` scrie că plafonul le acoperă pe amândouă („un plafon care
  // acoperă o singură cale nu e un plafon"), dar până acum niciun test nu cerea
  // asta: măsurat, cu `argonHash` scos de sub `gated`, toată suita rămânea
  // verde (349/349), iar 8 `hashPassword` simultane duceau `rss` cu +384 MiB —
  // exact vârful pe care semaforul pretinde că îl ține. `argon2Load()` raporta
  // `{running: 0, waiting: 0}` în ambele cazuri, deci nici diagnosticul nu vedea
  // drumul ocolit; singurul lucru care îl vede e memoria.
  //
  // Calea prin care se ajunge aici din afară: schimbarea parolei operatorului și
  // crearea de conturi. Nu e o rută anonimă ca `/login`, dar plafonul e comun
  // celor două — o schimbare de parolă concomitentă cu o rafală de login ar
  // dubla vârful, iar ce moare la plafonul de memorie al planului e ingestia.
  //
  // Testul ăsta vine DUPĂ cel de mai sus, nu înaintea lui, și asta nu e o
  // preferință: `rss` e monoton, deci o rafală de hashuri nepăzită l-ar urca
  // definitiv, iar măsurătoarea verificărilor ar porni de pe platoul ăla și ar
  // trece verde fără să dovedească nimic.
  const burst = 8;
  // O trecere înainte de măsurare, ca `rss` să fie deja pe platoul unei singure
  // alocări de 64 MiB — altfel prima alocare din rafală s-ar citi ca o creștere.
  await hashPassword(PASSWORD);

  const before = process.memoryUsage.rss();
  const started = process.hrtime.bigint();
  const hashes = await Promise.all(
    Array.from({ length: burst }, () => hashPassword(PASSWORD)));
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  const grewMiB = (process.memoryUsage.rss() - before) / MIB;

  // Întâi: măsurătoarea are ce măsura. O implementare care ar întoarce un șir
  // fără să calculeze nimic n-ar aloca nici ea memorie, deci ar trece pragul de
  // mai jos fără să dovedească nimic. Sarea e aleatoare, deci hashurile diferă.
  assert.equal(new Set(hashes).size, burst, "hashuri identice: nu s-a calculat");
  for (const one of hashes) {
    assert.match(one, /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$/, "nu e un hash PHC");
  }
  assert.ok(ms > burst * 20,
            `${burst} hashuri au durat ${ms.toFixed(0)} ms; la m=65536,t=3 nu se ` +
            "poate, deci nu s-a calculat nimic și măsurătoarea de memorie de mai " +
            "jos nu spune nimic");

  // Același prag ca la verificări, și din același motiv: cu semafor creșterea e
  // ~0 MiB, fără el ar fi ~8 × 64 = 512 MiB (măsurat: +384).
  assert.ok(grewMiB < 2 * PER_VERIFICATION_MIB,
            `o rafală de ${burst} hashuri a crescut rss cu ${grewMiB.toFixed(0)} ` +
            `MiB (prag: ${2 * PER_VERIFICATION_MIB}). Deci hashingul NU trece prin ` +
            "semafor, iar plafonul acoperă o singură cale — o schimbare de parolă " +
            "poate omorî procesul care ingerează arhiva de dovezi");

  assert.deepEqual(argon2Load(), { running: 0, waiting: 0 });
});

test("coada are un capăt, iar peste el se REFUZĂ, nu se așteaptă", async () => {
  // O coadă nemărginită e tot un mod de a rămâne fără memorie, doar mai lent:
  // fiecare cerere care așteaptă ține în viață corpul ei și continuarea rutei,
  // iar operatorul ajunge în spatele unei cozi pe care nimic n-o golește.
  //
  // Refuzul trebuie să fie DISTINCT de „parolă greșită": întors ca verdict, ar
  // număra o încercare eșuată pentru un cont care n-a greșit nimic — adică
  // blocarea contului operatorului printr-o rafală anonimă, exact atacul pe care
  // limitarea de rată ar trebui să-l oprească.
  const hash = await hashPassword(PASSWORD);
  const accepted = MAX_CONCURRENT_ARGON2 + MAX_QUEUED_ARGON2;
  const total = accepted + 3;

  const settled = await Promise.allSettled(
    Array.from({ length: total }, () => verifyPassword(hash, PASSWORD)));

  const refused = settled.filter((s) => s.status === "rejected");
  const done = settled.filter((s) => s.status === "fulfilled");
  assert.equal(done.length, accepted,
               `${done.length} verificări au fost primite, iar plafonul e ${accepted}`);
  assert.equal(refused.length, total - accepted);
  for (const one of refused) {
    assert.ok((one as PromiseRejectedResult).reason instanceof PasswordBusyError,
              `refuzul de supraîncărcare a ieșit ca ${(one as PromiseRejectedResult).reason}`);
  }
  for (const one of done) {
    assert.deepEqual((one as PromiseFulfilledResult<unknown>).value,
                     { ok: true, needsRehash: false },
                     "o cerere primită a răspuns altceva decât verdictul ei");
  }

  // Iar refuzul nu costă permisul: după rafală, autentificarea merge mai departe.
  assert.deepEqual(argon2Load(), { running: 0, waiting: 0 });
  assert.deepEqual(await verifyPassword(hash, PASSWORD),
                   { ok: true, needsRehash: false });
});

test("refuzul de supraîncărcare nu spune dacă utilizatorul există", async () => {
  // Plafonul se atinge ÎNAINTE de orice ramificare pe `storedHash`, deci ramura
  // fără utilizator trebuie să fie refuzată la fel. Altfel plafonul ar deveni el
  // însuși oracolul de enumerare pe care îl apără hashul-fantomă: „503 aici, 401
  // dincolo" spune ce nume există, la fel de bine ca o diferență de timp.
  const hash = await hashPassword(PASSWORD);
  const total = MAX_CONCURRENT_ARGON2 + MAX_QUEUED_ARGON2 + 2;

  const settled = await Promise.allSettled(
    Array.from({ length: total }, (_, i) =>
      // Ultimele două — cele care vor fi refuzate — sunt pe ramura FĂRĂ
      // utilizator. Ordinea e deterministă: cererile intră în semafor în ordinea
      // în care au fost create.
      verifyPassword(i < total - 2 ? hash : null, PASSWORD)));

  const refused = settled.filter((s) => s.status === "rejected");
  assert.equal(refused.length, 2, "ramura fără utilizator n-a fost refuzată");
  for (const one of refused) {
    assert.ok((one as PromiseRejectedResult).reason instanceof PasswordBusyError);
  }
  assert.deepEqual(argon2Load(), { running: 0, waiting: 0 });
});

/**
 * Câte microactivități poate arde bucla de observare de mai jos înainte să
 * renunțe. Măsurat, rafala se termină în ~170; plafonul e la 1 000 000 fiindcă
 * el nu e o margine de timp, ci apărarea împotriva unei bucle care ar înfometa
 * bucla de evenimente la nesfârșit (dacă Argon2 ar ajunge vreodată să aștepte o
 * MACROactivitate, microactivitatea noastră n-ar mai lăsa-o să ruleze).
 */
const OBSERVER_TICK_LIMIT = 1_000_000;

test("permisul se PREDĂ: `running` nu scade cât timp coada e nevidă", async () => {
  // Fereastra pe care o închide predarea, scrisă în `acquire`: dacă `release` ar
  // scădea contorul ÎNAINTE să trezească pe cineva, între trezire și repornirea
  // efectivă a celui trezit trece o microactivitate în care contorul e liber cu
  // coada nevidă. Un apel nou sosit atunci ar intra pe calea rapidă, după care ar
  // intra și cel trezit: doi calcule în zbor cu plafonul pe unu, adică 128 MiB în
  // loc de 64 — plafonul care raportează că e respectat fără să fie.
  //
  // Se afirmase că proprietatea asta e corectă prin construcție dar netestabilă,
  // fiindcă Node golește microactivitățile înaintea macroactivităților. Nu e:
  // fereastra se vede TOT dintr-o microactivitate. Bucla de mai jos numără
  // momentele în care `running === 0` cu coada nevidă — ceea ce predarea nu are
  // voie să producă niciodată, iar varianta naivă produce la fiecare trezire
  // (măsurat: 0 aici, 4 acolo).
  //
  // Practic fereastra nu e exploatabilă din HTTP — cererile sosesc din
  // macroactivități, deci n-ar nimeri niciodată în ea. Ce se apără e argumentul:
  // predarea ocupă un paragraf întreg în docstring și, fără cifra asta, e o
  // afirmație pe care nimeni n-a verificat-o.
  const hash = await hashPassword(PASSWORD);
  const burst = 5;   // unul în zbor, patru la coadă, deci patru predări

  let finished = false;
  const work = Promise.all(
    Array.from({ length: burst }, () => verifyPassword(hash, PASSWORD)),
  ).then(() => { finished = true; });

  let ticks = 0;
  let gaps = 0;
  let handovers = 0;
  let deepestQueue = 0;
  let previousQueue = argon2Load().waiting;
  while (!finished && ticks < OBSERVER_TICK_LIMIT) {
    await Promise.resolve();
    ticks++;
    const load = argon2Load();
    if (load.waiting < previousQueue) handovers++;
    if (load.running === 0 && load.waiting > 0) gaps++;
    deepestQueue = Math.max(deepestQueue, load.waiting);
    previousQueue = load.waiting;
  }
  // Dacă bucla s-a oprit la plafon, ea NU a văzut rafala până la capăt, deci
  // `gaps === 0` n-ar spune nimic: „n-am observat" nu e „nu s-a întâmplat".
  const watchedToTheEnd = finished;
  await work;

  assert.ok(watchedToTheEnd,
            `bucla de observare s-a oprit după ${ticks} microactivități, cu rafala ` +
            "încă în curs. N-a văzut nicio predare, deci nu poate spune nimic " +
            "despre ele.");
  // Și chiar a existat o coadă peste care să se predea ceva: fără asta, o
  // implementare care ar rula rafala serial, fără să pună pe nimeni la coadă, ar
  // trece cu `gaps === 0` fără să fi trecut prin fereastra măsurată.
  assert.equal(deepestQueue, burst - 1,
               `coada cea mai adâncă observată a fost ${deepestQueue}, nu ${burst - 1}`);
  assert.equal(handovers, burst - 1,
               `am observat ${handovers} predări din ${burst - 1}; bucla n-a fost ` +
               "trează la fiecare, deci n-a putut vedea fereastra fiecăreia");

  assert.equal(gaps, 0,
               `în ${ticks} microactivități, contorul a fost 0 cu coada nevidă de ` +
               `${gaps} ori. Permisul se recâștigă prin recitirea contorului, nu se ` +
               "predă, deci o cerere sosită în fereastra aia intră peste cel trezit: " +
               "două calcule Argon2 în zbor cu plafonul pe unu.");
  assert.deepEqual(argon2Load(), { running: 0, waiting: 0 });
});
