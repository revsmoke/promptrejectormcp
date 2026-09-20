// Explicit live diagnostic only. Run npm run build first, then:
// node dist/scripts/calibrateTasteTester.js --live --config config/ai.example.json --max-requests 20 --max-usd 1 --samples 1
// Provider keys are read from the process environment. The chosen config must
// contain a rate card. Historical intent labels are never behavioral accuracy.
import { runCalibration } from '../src/scripts/calibrateTasteTester.js';
runCalibration(process.argv.slice(2)).catch(error => { console.error(error instanceof Error ? error.message : 'Calibration failed'); process.exitCode = 1; });
