/**
 * Secretele instanțelor, cifrate în repaus.
 *
 * Oglindește `TOTPCipher` din `sentinel/web/security.py:142`: un singur secret
 * principal în mediu, subchei separate per scop prin HKDF-SHA256, iar în bază
 * ajunge doar text cifrat. Proprietatea cerută e simplă de enunțat și ușor de
 * pierdut: **un dump al bazei, singur, nu trebuie să dea chei cu care se pot
 * fabrica loturi.** Cheia de expediere a unei instanțe e exact ce-i trebuie
 * cuiva ca să trimită agregatorului istorie inventată în numele unui server.
 *
 * ## Ce e diferit față de `TOTPCipher`, și de ce
 *
 * **AES-256-GCM cu date asociate (AAD), nu Fernet.** Fernet n-are AAD. Fără
 * ele, un blob cifrat e valid oriunde: cine poate scrie în bază (o injecție
 * SQL, un backup restaurat parțial, un panou de administrare al găzduirii) mută
 * textul cifrat al instanței A pe rândul instanței B, iar B începe să
 * autentifice cu cheia lui A — adică fix proprietatea „root pe A nu poate
 * fabrica date pentru B" pierdută fără ca nimic să pară stricat. Aici AAD e
 * `<instance_id>|<coloană>`, deci un blob mutat pe alt rând sau în altă coloană
 * nu se mai deschide.
 *
 * **Secret principal propriu (`SENTINEL_AGGREGATOR_SECRET`), nu cel de sesiune.**
 * Planul propunea `SENTINEL_SESSION_SECRET`, prin analogie cu serverul. Diferă
 * ciclul de viață: rotirea secretului de sesiune e o operație normală, care
 * trebuie să deconecteze utilizatorii — nu să facă imposibilă decriptarea
 * cheilor de ingestie și să oprească tăcut sincronizarea tuturor instanțelor.
 * Docstring-ul lui `TOTPCipher.decrypt` descrie deja jumătatea asta de problemă
 * pe server („SENTINEL_SESSION_SECRET may have been rotated"); n-o repetăm aici
 * cu miză mai mare.
 *
 * Paragraful ăsta anticipa că și cheia de TOTP a panoului se va deriva din
 * secretul principal al agregatorului. NU se derivă: `lib/auth/totp.ts` o
 * derivă din `SENTINEL_SESSION_SECRET`, cu alt `info`, iar argumentul e chiar
 * cel de mai sus citit în cealaltă direcție — rotirea cheii de ingestie (ce faci
 * după compromiterea unei instanțe) n-are voie să ceară reînrolarea TOTP a
 * fiecărui om. Motivul complet e în capul lui `lib/auth/totp.ts`.
 *
 * ## Formatul jetonului
 *
 *     sag1.<b64url(iv)>.<b64url(ciphertext)>.<b64url(tag)>
 *
 * Text, nu binar, ca `TOTPCipher`: coloana rămâne citibilă într-un `SELECT` de
 * diagnostic fără să spună nimic, iar prefixul de versiune face ca o schimbare
 * viitoare de algoritm să fie o migrare, nu o ghicire.
 *
 * Decodarea base64 din Node e IERTĂTOARE — `Buffer.from("!!!", "base64url")`
 * întoarce un buffer, nu o eroare. Deci alfabetul se verifică explicit; altfel
 * un jeton stricat ar produce un buffer scurt și o eroare de deschidere care
 * arată identic cu una de falsificare.
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

/** Versiunea formatului. Se schimbă doar odată cu algoritmul. */
const VERSION = "sag1";

/** 96 de biți — nonce-ul recomandat pentru GCM, și cel pentru care garanția de
 *  unicitate la generare aleatoare e argumentată. */
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** Aceeași limită ca `_derive_key` din `security.py`: sub 32 de caractere,
 *  secretul principal nu e un secret, iar `install.sh` generează unul cu
 *  `openssl rand -hex 32`. */
export const MIN_MASTER_LENGTH = 32;

/**
 * Base64url STRICT: se acceptă doar codificarea canonică.
 *
 * `Buffer.from(x, "base64url")` e iertător în două feluri. Sare peste
 * caracterele pe care nu le cunoaște, deci gunoiul devine octeți; și ignoră
 * biții de umplutură ai ultimului caracter, deci mai multe șiruri DIFERITE
 * decodează la aceiași octeți. Măsurat aici: eticheta GCM are 16 octeți, adică
 * 22 de caractere din care ultimul poartă doar 2 biți utili — a schimba oricare
 * dintre ceilalți 4 dă un jeton diferit ca text și identic ca octeți.
 *
 * Nu e o spărtură în GCM (octeții autentificați rămân aceiași), dar e o
 * maleabilitate a REPREZENTĂRII, iar textul ăsta ajunge într-o coloană de bază
 * de date. Orice cod care compară, deduplică sau indexează jetonul ca șir ar
 * vedea două valori acolo unde e una. Singurul jeton acceptat pentru un
 * conținut e cel pe care îl produce `seal`.
 *
 * O singură verificare, nu două: re-codificarea le acoperă pe amândouă. O
 * versiune anterioară avea și o expresie regulată pentru alfabet, dar `"ab*cd"`
 * se re-codifică drept `"abcd"`, deci pică oricum aici — iar o cale a doua, pe
 * care nicio probă nu o poate deosebi de absența ei, e o cale care se șterge cu
 * suita verde.
 */
function decodeStrict(text: string): Buffer | null {
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) return null;
  return bytes;
}

export class CryptoConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoConfigError";
  }
}

/** Cui aparține textul cifrat. Obligatoriu la ambele capete — de-aia e un
 *  argument, nu o valoare implicită: un AAD care se poate uita nu e un AAD. */
export type SecretScope = {
  /**
   * Rândul pe care stă textul cifrat.
   *
   * Pentru secretele de expediere e `instance_id`. Pentru secretele TOTP ale
   * panoului (`lib/auth/totp.ts`) e `user:<id>` — alt fel de proprietar, același
   * AAD, fiindcă un al doilea format ar fi un al doilea lucru de ținut în acord.
   * Câmpul s-a numit `instanceId` până când a apărut al doilea proprietar;
   * OCTEȚII AAD n-au fost atinși de redenumire, iar asta e ținută de testul
   * „un jeton sigilat de o versiune anterioară se deschide și acum" din
   * `tests/crypto.test.ts`.
   */
  owner: string;
  /** Numele coloanei. Două secrete ale aceluiași proprietar nu sunt schimbabile. */
  field: string;
};

function aadFor(scope: SecretScope): Buffer {
  if (!scope.owner || !scope.field) {
    throw new CryptoConfigError(
      "AAD incomplet: cifrarea unui secret cere și proprietarul, și coloana. " +
      "Fără ele, un blob mutat de pe un rând pe altul s-ar decripta.");
  }
  // Separator care nu poate apărea într-un identificator de instanță
  // (`lib/ship-keys.ts` acceptă doar [a-zA-Z0-9._-]), deci perechea
  // (proprietar, coloană) nu poate fi ambiguă.
  return Buffer.from(`${VERSION}|${scope.owner}|${scope.field}`, "utf8");
}

/**
 * HKDF-SHA256 din secretul principal, subcheie per scop.
 *
 * `salt` de lungime zero, ca `salt=None` în varianta Python — aceeași
 * construcție HKDF. Scopul (`info`) e ce ține cheia de cifrare a secretelor
 * separată de cea de TOTP din E3: o slăbiciune într-un context nu trebuie să
 * devină una în celălalt.
 */
export function deriveKey(master: string, info: string): Buffer {
  if (typeof master !== "string" || master.length < MIN_MASTER_LENGTH) {
    throw new CryptoConfigError(
      `SENTINEL_AGGREGATOR_SECRET trebuie să aibă cel puțin ${MIN_MASTER_LENGTH} ` +
      "de caractere. Generează unul cu `openssl rand -hex 32`.");
  }
  if (!info) throw new CryptoConfigError("derivarea cheii cere un scop (info)");
  return Buffer.from(hkdfSync(
    "sha256", Buffer.from(master, "utf8"), Buffer.alloc(0),
    Buffer.from(info, "utf8"), KEY_BYTES));
}

/** Scopul folosit pentru secretele de expediere ale instanțelor. */
export const SHIP_SECRET_INFO = "sentinel-aggregator-instance-secret-v1";

export class SecretBox {
  private readonly key: Buffer;

  constructor(master: string, info: string = SHIP_SECRET_INFO) {
    this.key = deriveKey(master, info);
  }

  seal(plaintext: string, scope: SecretScope): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(aadFor(scope));
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [VERSION, iv.toString("base64url"), ciphertext.toString("base64url"),
            tag.toString("base64url")].join(".");
  }

  /**
   * Textul în clar, sau `null`.
   *
   * `null`, nu excepție — aceeași alegere ca `TOTPCipher.decrypt` și pentru
   * același motiv: un secret care nu se poate decripta înseamnă că secretul
   * principal a fost rotit sau că rândul a fost umblat. În ambele cazuri
   * reacția corectă e să REFUZI lotul, nu să cazi cu 500 în ruta de ingestie —
   * un agregator care nu mai poate răspunde nu mai poate nici să spună de ce.
   *
   * Apelantul e obligat să deosebească `null` de „secret gol": un `if (!secret)`
   * peste rezultat le confundă, iar confuzia aia e „lipsă de configurație"
   * raportată ca „refuz".
   */
  open(token: string, scope: SecretScope): string | null {
    if (typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 4 || parts[0] !== VERSION) return null;
    const [, ivRaw, ctRaw, tagRaw] = parts;
    const iv = decodeStrict(ivRaw);
    const ciphertext = decodeStrict(ctRaw);
    const tag = decodeStrict(tagRaw);
    if (iv === null || ciphertext === null || tag === null) return null;
    // Lungimea etichetei e un CONTROL DE SECURITATE, nu o verificare de formă.
    // Măsurat pe Node: `setAuthTag` acceptă etichete GCM de 4, 8, 12–15 octeți,
    // iar trunchierea GCM e definită ca primii biți ai etichetei întregi — deci
    // primii 4 octeți ai unei etichete valide SUNT o etichetă validă de 32 de
    // biți pentru același mesaj. Cine poate scrie coloana o taie la 4 octeți și
    // coboară efortul unei falsificări de la 2^128 la 2^32, adică din
    // imposibil în „câteva ore". Node doar avertizează (DEP0182); refuzul
    // trebuie să fie al nostru.
    if (tag.length !== TAG_BYTES) return null;
    // Lungimea IV-ului, în schimb, e o aserțiune de FORMAT: GCM acceptă IV-uri
    // de orice lungime, iar unul greșit produce oricum o autentificare eșuată.
    // Nu există probă care să deosebească linia asta de absența ei, și e scris
    // aici ca să nu caute nimeni testul care o acoperă. Se păstrează fiindcă
    // perechea documentează formatul și fiindcă un `seal` viitor cu alt IV ar
    // trebui să întâlnească un refuz, nu o decriptare care eșuează din alt motiv.
    if (iv.length !== IV_BYTES) return null;

    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
      decipher.setAAD(aadFor(scope));
      decipher.setAuthTag(tag);
      const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return out.toString("utf8");
    } catch {
      // Fără detalii în mesaj: textul unei erori de criptografie nu spune nimic
      // util operatorului și poate spune ceva atacatorului.
      return null;
    }
  }
}
