/**
 * Ce e comun fiecărei pagini de panou: cine ești, ce server privești, ce a sosit.
 *
 * Există ca să nu fie scris de nouă ori. Regula care alege serverul e cea mai
 * ușor de scris greșit din tot panoul, iar o a doua copie a ei e locul în care
 * apare divergența — exact motivul pentru care `lib/auth/scope.ts` are un
 * recensământ care numără locurile ce fabrică un domeniu.
 */

import { arrivalsFor } from "./data/arrivals";
import { visibleInstances } from "./data/instances";
import type { AuthDb } from "./auth/db";
import type { Chrome } from "./panel-page";
import type { InstanceScope } from "./auth/scope";
import type { Session } from "./auth/session";
import type { AuthUser } from "./auth/users";

/**
 * Serverul ales, dintre cele pe care contul chiar le vede.
 *
 * `cerut` vine din `?instanta=`, adică de la client. Nu e crezut: se caută în
 * lista permisă, iar dacă nu e acolo — inventat, șters, sau al altcuiva — se
 * cade pe primul permis. NU pe „toate" și nu pe eroare:
 *
 *   * „toate" ar transforma un identificator greșit într-o lărgire de vizibilitate,
 *     care e chiar direcția pe care autorizarea o apără;
 *   * o eroare ar face ca o legătură veche, către un server retras între timp,
 *     să ducă la un ecran mort în loc de panoul următorului server.
 *
 * `null` doar când contul nu vede niciun server. Aia e o stare reală și normală
 * pentru un cont proaspăt, iar paginile o spun ca atare.
 */
export function chooseInstance(
  instances: { instanceId: string }[], cerut: string | null,
): string | null {
  if (instances.length === 0) return null;
  if (cerut !== null && instances.some((i) => i.instanceId === cerut)) return cerut;
  return instances[0].instanceId;
}

export type Who = {
  user: AuthUser;
  session: Session;
  allowedInstanceIds: InstanceScope;
};

/**
 * Antetul paginii curente, plus ce a sosit de la serverul ales.
 *
 * `arrivals` se citește pentru serverul ALES, nu pentru toate: pagina vorbește
 * despre un singur server, iar „fluxul ăsta nu se expediază" e o afirmație
 * despre el, nu despre flotă. Adunate, un flux care curge de pe A ar face
 * pagina lui B să pară alimentată.
 */
export async function buildChrome(
  req: Request, db: AuthDb, who: Who, active: string,
): Promise<Chrome> {
  const instances = await visibleInstances(db, who.allowedInstanceIds);
  const cerut = new URL(req.url).searchParams.get("instanta");
  const selected = chooseInstance(instances, cerut);

  return {
    username: who.user.username,
    csrfToken: who.session.csrfToken,
    instances,
    selected,
    active,
    arrivals: selected === null
      ? new Map()
      : await arrivalsFor(db, who.allowedInstanceIds, selected),
  };
}
