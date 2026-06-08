import { describe, it, expect } from 'vitest';
import { extractHashtags, validateNodeUrl } from './utils';

describe('validateNodeUrl (SSRF, audit B4.2)', () => {
  it('accepts public https nodes', () => {
    expect(validateNodeUrl('https://node.ogmara.org')).toBe('https://node.ogmara.org');
  });
  it('rejects http in web (non-private) mode', () => {
    expect(validateNodeUrl('http://node.ogmara.org')).toBeNull();
  });
  it('rejects loopback/private literals', () => {
    expect(validateNodeUrl('https://127.0.0.1')).toBeNull();
    expect(validateNodeUrl('https://10.0.0.1')).toBeNull();
    expect(validateNodeUrl('https://192.168.1.1')).toBeNull();
    expect(validateNodeUrl('https://169.254.169.254')).toBeNull(); // cloud metadata
    expect(validateNodeUrl('https://100.64.0.1')).toBeNull(); // CGNAT
    expect(validateNodeUrl('https://localhost')).toBeNull();
  });
  it('rejects decimal/hex/octal-encoded private IPv4 (canonicalized by URL)', () => {
    expect(validateNodeUrl('https://2130706433')).toBeNull(); // 127.0.0.1
    expect(validateNodeUrl('https://0x7f000001')).toBeNull();
    expect(validateNodeUrl('https://0177.0.0.1')).toBeNull();
  });
  it('rejects IPv4-mapped / private IPv6', () => {
    expect(validateNodeUrl('https://[::1]')).toBeNull();
    expect(validateNodeUrl('https://[::ffff:127.0.0.1]')).toBeNull();
    expect(validateNodeUrl('https://[fd00::1]')).toBeNull(); // ULA
  });
  it('rejects non-http(s) schemes and over-long urls', () => {
    expect(validateNodeUrl('file:///etc/passwd')).toBeNull();
    expect(validateNodeUrl('https://' + 'a'.repeat(300))).toBeNull();
  });
  it('allows private/loopback when allowPrivateHosts (desktop/mobile local trust)', () => {
    expect(validateNodeUrl('http://localhost:41721', { allowPrivateHosts: true }))
      .toBe('http://localhost:41721');
    expect(validateNodeUrl('http://192.168.1.50:41721', { allowPrivateHosts: true }))
      .toBe('http://192.168.1.50:41721');
  });
});

describe('extractHashtags', () => {
  it('should extract basic hashtags', () => {
    expect(extractHashtags('#hello world #test')).toEqual(['hello', 'test']);
  });

  it('should lowercase hashtags', () => {
    expect(extractHashtags('#Hello #WORLD')).toEqual(['hello', 'world']);
  });

  it('should deduplicate', () => {
    expect(extractHashtags('#hello #hello #Hello')).toEqual(['hello']);
  });

  it('should limit to 10 tags', () => {
    const text = Array.from({ length: 15 }, (_, i) => `#tag${i}`).join(' ');
    expect(extractHashtags(text)).toHaveLength(10);
  });

  it('should handle empty text', () => {
    expect(extractHashtags('')).toEqual([]);
  });

  it('should handle text without hashtags', () => {
    expect(extractHashtags('no tags here')).toEqual([]);
  });

  it('should handle hashtags with underscores', () => {
    expect(extractHashtags('#hello_world')).toEqual(['hello_world']);
  });

  it('should not match bare # or #', () => {
    expect(extractHashtags('# not a tag')).toEqual([]);
  });
});
