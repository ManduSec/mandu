/** Read the doctor's JSON report from stdout followed by launcher diagnostics.
 * Property order and pretty-printing are not part of the report contract.
 */
import type { DoctorSecretsReport } from "../../launcher/src/doctor-secrets.js";

type FixtureReport = Pick<DoctorSecretsReport, "roots" | "files" | "notCovered" | "launch">;

export function doctorSecretsReport(out: string): FixtureReport {
  // JSON.parse decides the boundaries: braces in JSON strings and nested
  // objects cannot terminate a report. Ignore unrelated diagnostic objects.
  const starts = [...out.matchAll(/^[ \t]*\{/gm)].map((m) => m.index);
  const ends = [...out.matchAll(/\}[ \t]*(?=\r?$)/gm)].map((m) => m.index + 1);
  for (const start of starts) {
    for (const end of ends) {
      if (end <= start) continue;
      let value: unknown;
      try { value = JSON.parse(out.slice(start, end)); } catch { continue; }
      if (isReport(value)) return value;
    }
  }
  throw new Error(`no dry-run JSON report in output:\n${out.slice(-800)}`);
}

function isReport(value: unknown): value is FixtureReport {
  if (value === null || typeof value !== "object") return false;
  const report = value as Partial<DoctorSecretsReport>;
  return Array.isArray(report.roots) && Array.isArray(report.files) &&
    report.notCovered !== null && typeof report.notCovered === "object" &&
    report.notCovered.counts !== null && typeof report.notCovered.counts === "object" &&
    !Array.isArray(report.notCovered.counts) && typeof report.notCovered.truncated === "boolean" &&
    report.launch !== null && typeof report.launch === "object" && typeof report.launch.ok === "boolean";
}
