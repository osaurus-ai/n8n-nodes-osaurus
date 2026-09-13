import { describe, expect, it } from 'vitest';

import { collectSseContent, parseSseFrames } from '../src/sse';

const STREAM = [
	'data: {"choices":[{"delta":{"content":"PO"}}]}',
	'',
	'data: {"choices":[{"delta":{"content":"NG"}}]}',
	'',
	'data: [DONE]',
	'',
].join('\n');

describe('collectSseContent', () => {
	it('concatenates choice deltas until [DONE]', () => {
		const { content, frames } = collectSseContent(STREAM);
		expect(content).toBe('PONG');
		expect(frames[frames.length - 1]?.data).toBe('[DONE]');
	});

	it('parses named events and ignores comments', () => {
		const frames = parseSseFrames(': keep-alive\nevent: hint\ndata: {"ok":true}\n\n');
		expect(frames).toEqual([{ event: 'hint', data: '{"ok":true}' }]);
	});
});
