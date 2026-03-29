import { describe, it, expect } from 'vitest';
import { extractHashtags } from './utils';

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
