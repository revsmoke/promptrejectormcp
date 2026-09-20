import type { Services } from '../bootstrap.js';
import { isSizeError } from '../ai/schemas.js';
import { tasterInputSchema } from '../schemas/TasterReportSchema.js';
export async function handleMcpTaster(services: Services, input: unknown, signal?: AbortSignal) {
    const parsed = tasterInputSchema.safeParse(input ?? {});
    const error = (code: string) => ({ isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: code }) }] });
    if (!parsed.success)
        return error(isSizeError(parsed.error) ? 'input_too_large' : 'invalid_input');
    const { reportVersion, ...request } = parsed.data;
    const result = await services.tasteTesterService.runV2(request, { signal });
    return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
}
