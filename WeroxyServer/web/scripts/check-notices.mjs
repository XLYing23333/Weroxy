// No dependency or network access: fail builds with stale license inventory.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const notices = readFileSync(new URL("../../THIRD_PARTY_NOTICES", import.meta.url), "utf8");
for (const file of ["package.json", "package-lock.json"]) {
  const bytes = readFileSync(new URL("../" + file, import.meta.url));
  const hash = createHash("sha256").update(bytes).digest("hex");
  if (!notices.includes(hash + "  WeroxyServer/web/" + file + "\n")) {
    throw new Error("Third-party notices are stale; run scripts/third_party_notices.py --update and review the license evidence.");
  }
}
