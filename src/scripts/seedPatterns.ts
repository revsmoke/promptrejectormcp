/**
 * One-time script to generate patterns/manifest.json from existing pattern files.
 * Run with: npx ts-node src/scripts/seedPatterns.ts
 *
 * This script:
 * 1. Validates all pattern files against the schema
 * 2. Ensures all regex patterns compile
 * 3. Generates the manifest with SHA-256 hashes and HMAC signature
 */
import dotenv from "dotenv";
dotenv.config({ quiet: true } as any);

import { PatternService } from "../services/PatternService.js";
import { PatternFileSchema } from "../schemas/PatternSchemas.js";
import { readFileSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const thisFile = fileURLToPath(import.meta.url);
let projectRoot = dirname(thisFile);
while (projectRoot !== "/" && !readdirSync(projectRoot).includes("package.json")) {
    projectRoot = dirname(projectRoot);
}

const patternsDir = join(projectRoot, "patterns");
console.log(`[seed] Patterns directory: ${patternsDir}`);

// 1. Validate all pattern files
const files = readdirSync(patternsDir).filter(
    (f) => f.endsWith(".json") && f !== "manifest.json"
);

let totalPatterns = 0;
let errors = 0;

for (const file of files) {
    const filePath = join(patternsDir, file);
    const raw = readFileSync(filePath, "utf-8");

    try {
        const parsed = JSON.parse(raw);
        const validated = PatternFileSchema.parse(parsed);
        console.log(`[seed] ${file}: ${validated.patterns.length} patterns OK`);
        totalPatterns += validated.patterns.length;

        // Verify each regex compiles
        for (const p of validated.patterns) {
            try {
                new RegExp(p.pattern, p.flags);
            } catch (err) {
                console.error(`[seed] ERROR: Pattern "${p.id}" has invalid regex: ${err}`);
                errors++;
            }
        }
    } catch (err) {
        console.error(`[seed] ERROR validating ${file}:`, err);
        errors++;
    }
}

if (errors > 0) {
    console.error(`[seed] ${errors} error(s) found. Fix them before generating manifest.`);
    process.exit(1);
}

console.log(`[seed] Total patterns validated: ${totalPatterns}`);

// 2. Generate manifest
const service = new PatternService(patternsDir);
service.regenerateManifest();

// 3. Verify the generated manifest
const result = service.verify();
if (result.valid) {
    console.log(`[seed] Manifest generated and verified successfully.`);
    console.log(`[seed] HMAC signed: ${result.hmacValid !== null ? "yes" : "no (secret not set)"}`);
} else {
    console.error(`[seed] Manifest verification FAILED:`, result.errors);
    process.exit(1);
}
