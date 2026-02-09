import { createHash, createHmac } from "crypto";
import { readFileSync, writeFileSync, existsSync, renameSync, readdirSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import {
    PatternEntrySchema,
    PatternFileSchema,
    ManifestSchema,
    type PatternEntry,
    type PatternFile,
    type ManifestFile,
    type IntegrityCheckResult,
} from "../schemas/PatternSchemas.js";
import { FALLBACK_PATTERNS } from "./fallbackPatterns.js";

export interface ActivePattern {
    entry: PatternEntry;
    regex: RegExp;
}

export interface PatternListFilters {
    category?: string;
    flagGroup?: string;
    scope?: "general" | "skill";
    enabled?: boolean;
}

export class PatternService {
    private patternsDir: string;
    private manifestPath: string;
    private hmacSecret: string | null;
    private cache: PatternEntry[] = [];
    private fallbackActive = false;

    constructor(patternsDir?: string) {
        if (patternsDir) {
            this.patternsDir = patternsDir;
        } else {
            // Walk up from this file to find project root (where package.json lives)
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            while (dir !== "/" && !existsSync(join(dir, "package.json"))) {
                dir = dirname(dir);
            }
            this.patternsDir = join(dir, "patterns");
        }

        this.manifestPath = join(this.patternsDir, "manifest.json");
        this.hmacSecret = process.env.PATTERN_INTEGRITY_SECRET || null;

        if (!this.hmacSecret) {
            console.error("[PatternService] WARNING: PATTERN_INTEGRITY_SECRET not set. HMAC verification disabled.");
        }

        this.initialize();
    }

    private initialize(): void {
        if (!existsSync(this.patternsDir) || !existsSync(this.manifestPath)) {
            console.error("[PatternService] CRITICAL: Pattern directory or manifest missing. Loading fallback patterns.");
            this.loadFallbackPatterns();
            return;
        }

        const integrity = this.verify();
        if (!integrity.valid) {
            console.error("[PatternService] CRITICAL: Integrity verification failed. Loading fallback patterns.");
            console.error("[PatternService] Errors:", integrity.errors);
            this.loadFallbackPatterns();
            return;
        }

        this.loadAllPatterns();
    }

    private loadFallbackPatterns(): void {
        this.cache = [...FALLBACK_PATTERNS];
        this.fallbackActive = true;
    }

    private loadAllPatterns(): void {
        this.cache = [];
        this.fallbackActive = false;

        const files = readdirSync(this.patternsDir).filter(
            (f) => f.endsWith(".json") && f !== "manifest.json"
        );

        for (const file of files) {
            const filePath = join(this.patternsDir, file);
            try {
                const raw = readFileSync(filePath, "utf-8");
                const parsed = JSON.parse(raw);
                const validated = PatternFileSchema.parse(parsed);
                this.cache.push(...validated.patterns);
            } catch (err) {
                console.error(`[PatternService] Error loading ${file}:`, err);
            }
        }
    }

    // --- Public API ---

    list(filters?: PatternListFilters): PatternEntry[] {
        let results = [...this.cache];
        if (filters?.category) {
            results = results.filter((p) => p.category === filters.category);
        }
        if (filters?.flagGroup) {
            results = results.filter((p) => p.flagGroup === filters.flagGroup);
        }
        if (filters?.scope) {
            results = results.filter((p) => p.scope === filters.scope);
        }
        if (filters?.enabled !== undefined) {
            results = results.filter((p) => p.enabled === filters.enabled);
        }
        return results;
    }

    get(id: string): PatternEntry | undefined {
        return this.cache.find((p) => p.id === id);
    }

    /**
     * Returns fresh RegExp instances for active patterns in the given scope.
     * Fresh instances avoid lastIndex state pollution on global regexes.
     */
    getActivePatterns(scope: "general" | "skill"): ActivePattern[] {
        return this.cache
            .filter((p) => p.enabled && p.scope === scope)
            .map((entry) => ({
                entry,
                regex: new RegExp(entry.pattern, entry.flags),
            }));
    }

    add(pattern: Omit<PatternEntry, "id"> & { id?: string }): PatternEntry {
        const id = pattern.id || this.generateId(pattern.name);
        const entry = PatternEntrySchema.parse({ ...pattern, id });

        // Validate regex compiles
        try {
            new RegExp(entry.pattern, entry.flags);
        } catch (err) {
            throw new Error(`Invalid regex pattern: ${err}`);
        }

        // Check for duplicate ID
        if (this.cache.some((p) => p.id === entry.id)) {
            throw new Error(`Pattern with ID "${entry.id}" already exists`);
        }

        // Determine target file
        const targetFile = this.getTargetFile(entry);
        this.appendToFile(targetFile, entry);
        this.cache.push(entry);
        this.regenerateManifest();

        return entry;
    }

    update(id: string, changes: Partial<Omit<PatternEntry, "id">>): PatternEntry {
        const idx = this.cache.findIndex((p) => p.id === id);
        if (idx === -1) {
            throw new Error(`Pattern "${id}" not found`);
        }

        const updated = PatternEntrySchema.parse({ ...this.cache[idx], ...changes });

        // Validate regex if pattern changed
        if (changes.pattern || changes.flags) {
            try {
                new RegExp(updated.pattern, updated.flags);
            } catch (err) {
                throw new Error(`Invalid regex pattern: ${err}`);
            }
        }

        this.cache[idx] = updated;
        this.rewriteFileContaining(id, updated);
        this.regenerateManifest();

        return updated;
    }

    disable(id: string): PatternEntry {
        return this.update(id, { enabled: false });
    }

    import(patterns: Array<Omit<PatternEntry, "id"> & { id?: string }>): { imported: PatternEntry[]; skipped: string[] } {
        const imported: PatternEntry[] = [];
        const skipped: string[] = [];

        for (const p of patterns) {
            const id = p.id || this.generateId(p.name);
            if (this.cache.some((existing) => existing.id === id)) {
                skipped.push(id);
                continue;
            }
            try {
                const entry = this.add({ ...p, id });
                imported.push(entry);
            } catch (err) {
                skipped.push(id);
            }
        }

        return { imported, skipped };
    }

    verify(): IntegrityCheckResult {
        const result: IntegrityCheckResult = {
            valid: true,
            errors: [],
            checkedAt: new Date().toISOString(),
            fileResults: {},
            hmacValid: null,
        };

        // Load manifest
        if (!existsSync(this.manifestPath)) {
            result.valid = false;
            result.errors.push("Manifest file not found");
            return result;
        }

        let manifest: ManifestFile;
        try {
            const raw = readFileSync(this.manifestPath, "utf-8");
            manifest = ManifestSchema.parse(JSON.parse(raw));
        } catch (err) {
            result.valid = false;
            result.errors.push(`Invalid manifest: ${err}`);
            return result;
        }

        // Check each file hash
        for (const [filename, expected] of Object.entries(manifest.files)) {
            const filePath = join(this.patternsDir, filename);
            if (!existsSync(filePath)) {
                result.fileResults[filename] = { valid: false, error: "File not found" };
                result.errors.push(`Missing pattern file: ${filename}`);
                result.valid = false;
                continue;
            }

            const content = readFileSync(filePath, "utf-8");
            const hash = createHash("sha256").update(content).digest("hex");

            if (hash !== expected.sha256) {
                result.fileResults[filename] = { valid: false, error: "SHA-256 mismatch" };
                result.errors.push(`Hash mismatch for ${filename}`);
                result.valid = false;
            } else {
                result.fileResults[filename] = { valid: true };
            }
        }

        // Verify root hash
        const computedRootHash = this.computeRootHash(manifest.files);
        if (computedRootHash !== manifest.rootHash) {
            result.valid = false;
            result.errors.push("Root hash mismatch");
        }

        // Verify HMAC signature
        if (this.hmacSecret) {
            const expectedSig = createHmac("sha256", this.hmacSecret)
                .update(manifest.rootHash)
                .digest("hex");
            result.hmacValid = expectedSig === manifest.signature;
            if (!result.hmacValid) {
                result.valid = false;
                result.errors.push("HMAC signature mismatch");
            }
        } else {
            result.hmacValid = null; // HMAC not configured
        }

        return result;
    }

    isFallbackActive(): boolean {
        return this.fallbackActive;
    }

    // --- Private helpers ---

    private generateId(name: string): string {
        return name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "");
    }

    private getTargetFile(entry: PatternEntry): string {
        // Map categories to files
        const categoryFileMap: Record<string, string> = {
            xss: "xss.json",
            sqli: "sqli.json",
            shell_injection: "shell-injection.json",
            directory_traversal: "shell-injection.json",
        };

        if (entry.scope === "skill") {
            return "skill-threats.json";
        }

        return categoryFileMap[entry.category] || "custom.json";
    }

    private appendToFile(filename: string, entry: PatternEntry): void {
        const filePath = join(this.patternsDir, filename);
        let file: PatternFile;

        if (existsSync(filePath)) {
            const raw = readFileSync(filePath, "utf-8");
            file = PatternFileSchema.parse(JSON.parse(raw));
        } else {
            file = { version: 1, patterns: [] };
        }

        file.patterns.push(entry);
        this.atomicWrite(filePath, JSON.stringify(file, null, 2));
    }

    private rewriteFileContaining(id: string, updated: PatternEntry): void {
        // Find which file contains this pattern
        const files = readdirSync(this.patternsDir).filter(
            (f) => f.endsWith(".json") && f !== "manifest.json"
        );

        for (const file of files) {
            const filePath = join(this.patternsDir, file);
            const raw = readFileSync(filePath, "utf-8");
            const parsed = PatternFileSchema.parse(JSON.parse(raw));

            const idx = parsed.patterns.findIndex((p) => p.id === id);
            if (idx !== -1) {
                parsed.patterns[idx] = updated;
                this.atomicWrite(filePath, JSON.stringify(parsed, null, 2));
                return;
            }
        }

        throw new Error(`Pattern "${id}" not found in any file`);
    }

    private atomicWrite(filePath: string, content: string): void {
        const tmpPath = filePath + ".tmp";
        writeFileSync(tmpPath, content, "utf-8");
        renameSync(tmpPath, filePath);
    }

    private computeRootHash(files: Record<string, { sha256: string }>): string {
        const sortedNames = Object.keys(files).sort();
        const concatenated = sortedNames.map((n) => files[n].sha256).join("");
        return createHash("sha256").update(concatenated).digest("hex");
    }

    /**
     * Regenerate manifest.json after any mutation.
     * Computes SHA-256 for each pattern file, root hash, and HMAC signature.
     */
    regenerateManifest(): void {
        const files: Record<string, { sha256: string; patternCount: number }> = {};

        const patternFiles = readdirSync(this.patternsDir).filter(
            (f) => f.endsWith(".json") && f !== "manifest.json"
        );

        for (const file of patternFiles) {
            const filePath = join(this.patternsDir, file);
            const content = readFileSync(filePath, "utf-8");
            const hash = createHash("sha256").update(content).digest("hex");
            const parsed = JSON.parse(content);
            const patternCount = parsed.patterns?.length ?? 0;
            files[file] = { sha256: hash, patternCount };
        }

        const rootHash = this.computeRootHash(files);

        let signature = "";
        if (this.hmacSecret) {
            signature = createHmac("sha256", this.hmacSecret).update(rootHash).digest("hex");
        }

        const manifest: ManifestFile = {
            version: 1,
            generatedAt: new Date().toISOString(),
            files,
            rootHash,
            signature,
        };

        this.atomicWrite(this.manifestPath, JSON.stringify(manifest, null, 2));
    }
}
