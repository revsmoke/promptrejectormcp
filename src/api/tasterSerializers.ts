import type { Services } from '../bootstrap.js';
import { roleProfiles } from '../ai/config.js';
import { isSizeError } from '../ai/schemas.js';
import { tasterInputSchema } from '../schemas/TasterReportSchema.js';
export async function handleMcpTaster(services: Services, input: unknown, signal?: AbortSignal) {
    const parsed = tasterInputSchema.safeParse(input ?? {});
    const error = (code: string, extra: Record<string, unknown> = {}) => ({ isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: code, ...extra }) }] });
    if (!parsed.success)
        return error(isSizeError(parsed.error) ? 'input_too_large' : 'invalid_input');
    const { reportVersion = services.snapshot.config.mcpDefaultReportVersion, ...request } = parsed.data;
    if (reportVersion === 1 && [...roleProfiles(services.snapshot, 'taster'), ...roleProfiles(services.snapshot, 'monitor')].some(p => p.provider !== 'anthropic'))
        return error('report_version_required', { reportVersion: 2 });
    const result = reportVersion === 2 ? await services.tasteTesterService.runV2(request, { signal }) : await services.tasteTesterService.run(request, { signal });
    return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
}
