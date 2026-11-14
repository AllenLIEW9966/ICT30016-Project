/** Return a safe module-level bcrypt import insertion for a generated patch. */
export function bcryptImportInsertion(source: string, replacement: string, eol: string): { offset: number; text: string } | undefined {
  const mask = (text: string) => text.replace(
    /(?:[rRuUbBfF]{1,2})?(?:'''[\s\S]*?'''|"""[\s\S]*?"""|'(?:\\.|[^'\\\r\n])*'|"(?:\\.|[^"\\\r\n])*")|#[^\r\n]*/g,
    value => value.replace(/[^\r\n]/g, ' '),
  );
  if (!/\bbcrypt\s*\./.test(mask(replacement))) return undefined;
  const masked = mask(source);
  const imports: { start: number; end: number; code: string }[] = [];
  let consumed = 0;
  for (const match of masked.matchAll(/^(?:import\s+|from\s+\S+\s+import\b)/gm)) {
    const start = match.index!;
    if (masked.slice(consumed, start).trim()) break;
    let end = start;
    let depth = 0;
    for (; end < masked.length; end++) {
      const char = masked[end];
      if ('([{'.includes(char)) depth++;
      if (')]}'.includes(char)) depth--;
      if (char === '\n' && depth === 0 && !/\\\r?$/.test(masked.slice(start,end))) { end++; break; }
    }
    const code = masked.slice(start,end).replace(/\\\r?\n/g,' ');
    if (code.split(';').some(statement => /^\s*import\s+/.test(statement) && statement.replace(/^\s*import\s+/,'').split(',').some(part => /^\s*bcrypt(?:\s+as\s+bcrypt)?\s*$/.test(part)))) {
      return undefined;
    }
    imports.push({start,end,code});
    consumed = end;
  }
  const firstImport = imports.find(item => !/^from\s+__future__\b/.test(item.code));
  let offset = firstImport?.end ?? imports.at(-1)?.end;
  if (offset === undefined) {
    // Preserve shebang/encoding comments and the module docstring.
    const header = /^(?:\uFEFF)?(?:(?:[ \t]*#[^\r\n]*)?[ \t]*\r?\n)*/.exec(source)![0];
    offset = header.length;
    const docstring = /^(?:[rRuU])?(?:'''[\s\S]*?'''|"""[\s\S]*?"""|'(?:\\.|[^'\\\r\n])*'|"(?:\\.|[^"\\\r\n])*")/.exec(source.slice(offset));
    if (docstring) {
      const after = offset + docstring[0].length;
      const lineEnd = source.indexOf('\n',after);
      // Insertion before the next physical line also preserves inline statements.
      offset = lineEnd < 0 ? source.length : lineEnd + 1;
    }
  }
  return {offset, text:(offset > 0 && source[offset-1] !== '\n' ? eol : '') + 'import bcrypt' + eol};
}
