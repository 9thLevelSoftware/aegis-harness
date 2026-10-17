// A node:test reporter for CI: one GitHub Actions error annotation per failing test,
// because the job log is not always where the failure gets read.
const esc = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const prop = (s) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

export default async function* gha(source) {
  for await (const event of source) {
    if (event.type !== "test:fail") continue;
    const d = event.data;
    // Suites fail when a test in them fails; annotate the test only.
    if (d.details?.type === "suite") continue;
    const err = d.details?.error;
    const cause = err?.cause ?? err;
    const message = [cause?.message ?? String(cause ?? "failed"), cause?.actual !== undefined ? `actual: ${JSON.stringify(cause.actual)}` : "", cause?.expected !== undefined ? `expected: ${JSON.stringify(cause.expected)}` : ""].filter(Boolean).join("\n").slice(0, 3000);
    const file = d.file ? `file=${prop(d.file)},line=${d.line ?? 1},` : "";
    yield `::error ${file}title=${prop(d.name)}::${esc(message)}\n`;
  }
}
