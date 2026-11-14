export async function publishCurrentAdvisories<T>(
  query: () => Promise<T[]>,
  matchesContent: () => Promise<boolean>,
  isCurrent: () => boolean,
  publish: (items: T[]) => void,
  log: (message: string) => void = () => {},
): Promise<void> {
  try {
    const items = await query();
    if (!items.length) return;
    if (isCurrent() && await matchesContent() && isCurrent()) publish(items);
    else log('discarded stale response');
  } catch (error) {
    log('lookup failed: ' + (error instanceof Error ? error.name : 'unknown error'));
  }
}
