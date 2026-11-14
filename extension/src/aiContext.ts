/** Complete source lines with one-based original-file coordinates. */
export function aiSourceWindow(source: string, findingLine: number) {
  const lines = source.split(/\r\n|\n|\r/);
  const line = Math.max(1, Math.min(lines.length, Math.trunc(findingLine)));
  const start = Math.max(1, line - 20);
  const end = Math.min(lines.length, line + 20);
  return {
    source_window: lines.slice(start - 1, end).join('\n'),
    source_start_line: start,
    source_end_line: end,
    source_total_lines: lines.length,
  };
}
