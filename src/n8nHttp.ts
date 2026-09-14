import type {
	ICredentialTestFunctions,
	IExecuteFunctions,
	IHttpRequestOptions,
} from 'n8n-workflow';

import type { HttpFn, HttpResponse } from './secureChannel';

function bodyToString(body: unknown): string {
	if (body === undefined || body === null) return '';
	if (typeof body === 'string') return body;
	if (Buffer.isBuffer(body)) return body.toString('utf8');
	return JSON.stringify(body);
}

/** `HttpFn` over `this.helpers.httpRequest` (execute-time). Never throws on HTTP status. */
export function httpFromExecute(ctx: IExecuteFunctions): HttpFn {
	return async (request) => {
		const options: IHttpRequestOptions = {
			method: request.method,
			url: request.url,
			headers: request.headers,
			body: request.body,
			json: false,
			returnFullResponse: true,
			ignoreHttpStatusErrors: true,
			timeout: request.timeoutMs,
		};
		const response = (await ctx.helpers.httpRequest(options)) as {
			statusCode?: number;
			status?: number;
			body?: unknown;
		};
		return {
			status: response.statusCode ?? response.status ?? 0,
			body: bodyToString(response.body),
		} satisfies HttpResponse;
	};
}

/**
 * `HttpFn` over `this.helpers.request` — the only helper credential tests
 * expose. Same contract: statuses are returned, not thrown.
 */
export function httpFromCredentialTest(ctx: ICredentialTestFunctions): HttpFn {
	return async (request) => {
		const response = (await ctx.helpers.request({
			method: request.method,
			uri: request.url,
			headers: request.headers,
			body: request.body,
			resolveWithFullResponse: true,
			simple: false,
			timeout: request.timeoutMs,
		})) as { statusCode?: number; status?: number; body?: unknown };
		return {
			status: response.statusCode ?? response.status ?? 0,
			body: bodyToString(response.body),
		} satisfies HttpResponse;
	};
}
