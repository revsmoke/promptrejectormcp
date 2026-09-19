/** Provider-neutral mapping: an omitted ATLAS tag is preferable to an invented one. */
export function mapSecurityCategoriesToAtlas(categories: readonly string[]): string[] {
    const map: Record<string, string> = { unicode_smuggling: "AML.T0051", policy_puppetry: "AML.T0054", markdown_exfil: "AML.T0024", prompt_injection: "AML.T0051", obfuscation: "AML.T0051" };
    return [...new Set(categories.flatMap((category) => map[category] ? [map[category]] : []))];
}
