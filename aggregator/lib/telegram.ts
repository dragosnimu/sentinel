/**
 * Canalul de alarmă al martorului.
 *
 * Folosește ACELAȘI bot ca Sentinel, ceea ce e o decizie conștientă cu un
 * compromis de spus limpede:
 *
 * Un atacator cu root pe serverul monitorizat citește tokenul și poate trimite
 * mesaje care par ale Sentinel — de exemplu un „totul e în regulă" fals, chiar
 * înaintea alertei reale. Ce NU poate face e să oprească martorul să trimită,
 * iar asta e proprietatea pentru care există tot mecanismul.
 *
 * Atenuarea, fiindcă un bot separat costă un pas de configurare în plus:
 * mesajele martorului poartă un prefix pe care codul de pe server nu îl produce
 * niciodată. Nu e o dovadă criptografică — nimic trimis prin Telegram nu poate
 * fi — dar face confuzia deliberată vizibilă.
 */

const PREFIX = "🛰 MARTOR EXTERN";

/**
 * Escapare pentru `parse_mode: "HTML"`.
 *
 * Nu e cosmetică. Telegram RESPINGE tot mesajul dacă marcajul e stricat, deci
 * un `<` într-un text pus în mesaj — de exemplu eticheta unei instanțe, care
 * vine dintr-un payload semnat pe o mașină ce poate fi compromisă — nu strică
 * afișarea, ci oprește alerta. Exact modul în care canalul de alertare a fost
 * deja pierdut o dată, pentru un caracter.
 *
 * Cele trei caractere sunt fix cele cerute de documentația Telegram; nu se
 * escapează mai mult, fiindcă restul mesajului chiar folosește `<b>` și `<i>`.
 */
export function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export async function alert(text: string): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    console.error("[watcher] lipsesc TELEGRAM_BOT_TOKEN sau TELEGRAM_CHAT_ID");
    return false;
  }

  const body = {
    chat_id: chatId,
    parse_mode: "HTML",
    // Alertele astea nu respectă orele de liniște. Un server compromis la 3
    // dimineața nu așteaptă până la 6.
    disable_notification: false,
    text:
      `<b>${PREFIX}</b>\n` +
      `<i>Mesaj trimis din afara serverului monitorizat.</i>\n\n` +
      text,
  };

  // `cache` NU e în `RequestInit` sub tipurile lui Node — vine din lib.dom, care
  // nu e încărcat aici, fiindcă `document` și `window` n-au ce căuta ca tipuri
  // valide într-o aplicație care rulează doar pe server. `fetch` din Next îl
  // citește însă, deci câmpul rămâne și se declară pe obiectul ăsta. Scos „ca să
  // treacă tsc" ar fi fost o apărare care dispare fără ca cineva să decidă asta.
  const init: RequestInit & { cache?: "no-store" } = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    // Fără cache, oricât de improbabil ar fi pe un POST.
    cache: "no-store",
  };

  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, init);
    if (!r.ok) {
      console.error("[watcher] Telegram a refuzat", r.status, await r.text());
      return false;
    }
    return true;
  } catch (e) {
    console.error("[watcher] Telegram inaccesibil", e);
    return false;
  }
}
