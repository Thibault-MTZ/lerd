import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect, vi } from 'vitest';

const sdk = readFileSync(resolve(process.cwd(), '../../plugins/skeleton/ui/lerd.js'), 'utf8');

function context(search: string) {
  const host: any = { addEventListener: vi.fn(), parent: { postMessage: vi.fn() } };
  class ResizeObserver { observe() {} }
  new Function('window', 'location', 'ResizeObserver', 'document', sdk)(host, { search }, ResizeObserver, { documentElement: { scrollHeight: 100 } });
  return host.lerd.context;
}

describe('plugin SDK share context', () => {
  it('exposes the explicit action and keeps the native branch identity', () => {
    expect(context('?site=demo&domain=feat.demo.test&branch=feature-a&intent=access&lang=fr')).toEqual({ site: 'demo', domain: 'feat.demo.test', branch: 'feature-a', intent: 'access', lang: 'fr' });
  });
  it('does not invent an action for other plugin surfaces', () => {
    expect(context('').intent).toBe('');
  });
});
