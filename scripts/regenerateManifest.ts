// scripts/regenerateManifest.ts
//
// Rebuilds patterns/manifest.json with current SHA-256 hashes and (if a
// secret is set) an HMAC signature, then re-verifies. Run this after manually
// editing any file under patterns/ so the integrity check passes again.
//
// Required env vars:
//   PATTERN_INTEGRITY_SECRET  Optional but recommended. Without it the
//                             manifest still carries SHA-256 hashes (tamper
//                             detection) but lacks an HMAC signature
//                             (authenticity).
//
// Run with:
//   set -a; source .env; set +a
//   npx tsx scripts/regenerateManifest.ts
//
// Output: "Manifest regenerated", "Integrity check: PASSED|FAILED", pattern
// count, and whether the fallback set is active.
//
// Exit codes:
//   0  Always (errors are printed but not thrown). Inspect the "Integrity
//      check" line; "PASSED" means success.
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
