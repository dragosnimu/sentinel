/**
 * `GET /api/panel/instances` — ce servere vede contul autentificat.
 *
 * Prima rută a panoului care răspunde cu DATE, deci prima care poate greși
 * autorizarea. Ce o ține corectă nu e nimic scris aici: ruta n-are cum să
 * întrebe „toate instanțele" fiindcă `visibleInstances` nu are varianta aia —
 * al doilea parametru e obligatoriu, iar valoarea lui vine dintr-o citire din
 * `user_instances` făcută pentru sesiunea CERERII (`lib/auth/panel.ts`).
 *
 * **Un cont nou primește `[]`, nu tot.** E starea corectă, nu o eroare:
 * drepturile se dau explicit, cu `npm run user -- grant`. Probat prin efect, pe
 * un cont creat chiar de unealtă, în `tests/accounts.test.ts`.
 *
 * Panoul propriu-zis — HTML, nu JSON — e E3c. Aici e stratul de sub el.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { jsonResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { visibleInstances } from "@/lib/data/instances";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /api/panel/instances", async () => {
    const auth = await requirePanelUser(req, db);
    if (!auth.ok) return auth.response;

    return jsonResponse({
      instances: await visibleInstances(db, auth.who.allowedInstanceIds),
    });
  }, "json");
}
