import { PatternService } from "../src/services/PatternService.js";

// First instance loads fallback due to stale manifest, then regenerates
const svc = new PatternService();
svc.regenerateManifest();
console.log("Manifest regenerated");

// Second instance loads with the fresh manifest
const svc2 = new PatternService();
const integrity = svc2.verify();
console.log("Integrity check:", integrity.valid ? "PASSED" : "FAILED");
if (!integrity.valid) console.log("Errors:", integrity.errors);
console.log("Patterns loaded:", svc2.list().length);
console.log("Fallback active:", svc2.isFallbackActive());
