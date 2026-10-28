import { describe, it, expect, vi } from 'vitest';

// Read the shipped SDK without exposing its directory through Vite's dev server.
const nativeFs = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
const nativePath = await vi.importActual<{ resolve(...parts: string[]): string }>('node:path');
const nativeProcess = await vi.importActual<{ cwd(): string }>('node:process');
const sdk = nativeFs.readFileSync(nativePath.resolve(nativeProcess.cwd(), '../../plugins/skeleton/ui/lerd.js'), 'utf8');

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
