export type SseFrame = {
	event?: string;
	data: string;
};

/** Split an SSE document into frames. Blank lines delimit events. */
export function parseSseFrames(text: string): SseFrame[] {
	const frames: SseFrame[] = [];
	let event: string | undefined;
	const dataLines: string[] = [];

	const flush = () => {
		if (dataLines.length === 0 && event === undefined) {
			return;
		}
		frames.push({ event, data: dataLines.join('\n') });
		event = undefined;
		dataLines.length = 0;
	};

	for (const line of text.split(/\r?\n/)) {
		if (line === '') {
			flush();
			continue;
		}
		if (line.startsWith(':')) {
			continue;
		}
		if (line.startsWith('event:')) {
			event = line.slice('event:'.length).trim();
			continue;
		}
		if (line.startsWith('data:')) {
			dataLines.push(line.slice('data:'.length).replace(/^ /, ''));
		}
	}
	flush();
	return frames;
}

function deltaContent(payload: unknown): string {
	if (payload === null || typeof payload !== 'object') {
		return '';
	}
	const object = payload as {
		choices?: Array<{ delta?: { content?: unknown }; message?: { content?: unknown } }>;
	};
	const choice = object.choices?.[0];
	const fromDelta = choice?.delta?.content;
	if (typeof fromDelta === 'string') {
		return fromDelta;
	}
	const fromMessage = choice?.message?.content;
	return typeof fromMessage === 'string' ? fromMessage : '';
}

/**
 * Concatenate visible assistant text from an `/agents/{id}/run` SSE stream.
 * Stops at a `[DONE]` data frame.
 */
export function collectSseContent(text: string): { content: string; frames: SseFrame[] } {
	const frames = parseSseFrames(text);
	let content = '';
	for (const frame of frames) {
		if (frame.data === '[DONE]') {
			break;
		}
		try {
			content += deltaContent(JSON.parse(frame.data));
		} catch {
			// Non-JSON data frames are ignored for the visible answer.
		}
	}
	return { content, frames };
}
