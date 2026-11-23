/** Every word must appear somewhere in the row's displayed fields; an empty
 *  query matches everything, so clearing the box restores the full list. */
export function matchesQuery(query: string, fields: Array<string | null | undefined>): boolean {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = fields.filter((f) => f != null).join(" ").toLowerCase();
  return words.every((w) => haystack.includes(w));
}