/**
 * Intrarea unei unelte de linie de comandă, în cele două forme în care există.
 *
 * `isTTY` și `setRawMode` sunt tot ce deosebește un terminal de o conductă
 * pentru codul livrat, deci un flux care le poartă e cel mai apropiat lucru de
 * un terminal care se poate construi fără pseudo-terminal.
 *
 * Un singur loc, ca la `tests/shipped-files.ts`, și din același motiv: două
 * copii ale falsului terminal se pot desincroniza exact acolo unde contează.
 * Una căreia i-ar lipsi `setRawMode` ar face probele de prompt ascuns să treacă
 * pe un flux care nu e terminal — adică să nu deosebească nimic.
 *
 * Ce NU imită, scris ca să nu fie confundat: `stty` adevărat, ecoul shellului,
 * și faptul că un terminal real trimite câte un octet per apăsare. Că `stty`
 * chiar oprește ecoul se vede prima dată pe gazdă.
 */

import { PassThrough } from "node:stream";

export type FakeStdin = {
  stream: PassThrough;
  /** Fiecare comutare de mod brut, în ordine. `[true, false]` per prompt. */
  rawModes: boolean[];
};

export function fakeStdin(tty: boolean): FakeStdin {
  const stream = new PassThrough() as PassThrough
    & { isTTY?: boolean; setRawMode?: (mode: boolean) => void };
  const rawModes: boolean[] = [];
  if (tty) {
    stream.isTTY = true;
    stream.setRawMode = (mode: boolean) => { rawModes.push(mode); };
  }
  return { stream, rawModes };
}

/** Unde scrie unealta invitațiile. Se citește pe urmă, ca să se poată afirma că
 *  valoarea tastată NU a ajuns acolo. */
export function captureStderr(): { text: string; write(chunk: string): void } {
  const sink = {
    text: "",
    write(chunk: string) { sink.text += chunk; },
  };
  return sink;
}
