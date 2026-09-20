# Integration examples

Use a certificate trusted by the client runtime. For local development, install your local CA or configure the runtime’s CA file; do not disable certificate verification. Node/Python may need their CA environment settings even when the browser trusts localhost. See [TLS client setup](operations/local-server.md#client-certificate-trust).

### Node.js / Express Middleware

```javascript
async function promptSecurityMiddleware(req, res, next) {
  const userInput = req.body.message;

  const response = await fetch('https://localhost:3001/v2/check-prompt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: userInput })
  });

  const result = await response.json();

  if (!result.safe) {
    console.warn(`Blocked ${result.overallSeverity} threat:`, result.categories);
    return res.status(400).json({ error: 'Input rejected for security reasons' });
  }

  next();
}

// Usage
app.post('/chat', promptSecurityMiddleware, (req, res) => {
  // Safe to process req.body.message
});
```

### Python

```python
import requests
from typing import TypedDict

class SecurityResult(TypedDict):
    safe: bool
    decision: str
    overallSeverity: str
    categories: list[str]

def check_prompt_safety(user_input: str) -> SecurityResult:
    """Check if a prompt is safe before processing."""
    response = requests.post(
        'https://localhost:3001/v2/check-prompt',
        json={'prompt': user_input},
        timeout=25
    )
    response.raise_for_status()
    return response.json()

def process_user_input(user_input: str) -> str:
    result = check_prompt_safety(user_input)

    if not result['safe']:
        severity = result['overallSeverity']
        categories = ', '.join(result['categories'])
        raise ValueError(f"Input blocked ({severity}): {categories}")

    # Safe to proceed with your AI agent
    return your_ai_agent.process(user_input)
```

### Python with Async (aiohttp)

```python
import aiohttp

async def check_prompt_safety_async(user_input: str) -> dict:
    """Async version for high-throughput applications."""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            'https://localhost:3001/v2/check-prompt',
            json={'prompt': user_input}
        ) as response:
            return await response.json()

async def process_batch(prompts: list[str]) -> list[dict]:
    """Process multiple prompts concurrently."""
    import asyncio
    tasks = [check_prompt_safety_async(p) for p in prompts]
    return await asyncio.gather(*tasks)
```

### Go

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type CheckPromptRequest struct {
	Prompt string `json:"prompt"`
}

type SecurityResult struct {
	Safe             bool     `json:"safe"`
	Decision         string   `json:"decision"`
	OverallSeverity  string   `json:"overallSeverity"`
	Categories       []string `json:"categories"`
	Timestamp        string   `json:"timestamp"`
}

func CheckPromptSafety(prompt string) (*SecurityResult, error) {
	reqBody, err := json.Marshal(CheckPromptRequest{Prompt: prompt})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		"https://localhost:3001/v2/check-prompt",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SecurityResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func main() {
	result, err := CheckPromptSafety("Hello, help me with Go!")
	if err != nil {
		panic(err)
	}

	if !result.Safe {
		fmt.Printf("BLOCKED [%s]: %v\n", result.OverallSeverity, result.Categories)
		return
	}

	fmt.Println("Input is safe, proceeding...")
}
```

### Rust

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CheckPromptRequest {
    prompt: String,
}

#[derive(Deserialize, Debug)]
struct SecurityResult {
    safe: bool,
    decision: String,
    #[serde(rename = "overallSeverity")]
    overall_severity: String,
    categories: Vec<String>,
    timestamp: String,
}

async fn check_prompt_safety(prompt: &str) -> Result<SecurityResult, reqwest::Error> {
    let client = Client::new();
    let request = CheckPromptRequest {
        prompt: prompt.to_string(),
    };

    let response = client
        .post("https://localhost:3001/v2/check-prompt")
        .json(&request)
        .send()
        .await?
        .json::<SecurityResult>()
        .await?;

    Ok(response)
}

#[tokio::main]
async fn main() {
    let result = check_prompt_safety("Help me write a Rust function")
        .await
        .expect("Failed to check prompt");

    if !result.safe {
        eprintln!(
            "BLOCKED [{}]: {:?}",
            result.overall_severity, result.categories
        );
        return;
    }

    println!("Input is safe, proceeding...");
}
```

### cURL / Shell Script

```bash
#!/bin/bash

check_prompt() {
    local prompt="$1"
    local payload result
    payload=$(jq -n --arg prompt "$prompt" '{prompt: $prompt}') || return 1
    result=$(curl --fail --silent --show-error --max-time 25 \
        https://localhost:3001/v2/check-prompt \
        -H 'Content-Type: application/json' --data "$payload") || return 1
    # Missing, malformed, review, block and unavailable results never pass.
    jq -e '.decision == "allow" and .safe == true' <<< "$result" > /dev/null
}

# Usage
if check_prompt "Hello, help me with bash scripting"; then
    echo "Safe to proceed!"
else
    echo "Input was blocked"
    exit 1
fi
```

### PHP

```php
<?php

function checkPromptSafety(string $prompt): array {
    $ch = curl_init('https://localhost:3001/v2/check-prompt');

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['prompt' => $prompt]),
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    return json_decode($response, true);
}

// Usage
$result = checkPromptSafety($_POST['user_message']);

if (!$result['safe']) {
    http_response_code(400);
    die(json_encode([
        'error' => 'Input rejected',
        'severity' => $result['overallSeverity']
    ]));
}

// Safe to process
processUserMessage($_POST['user_message']);
```

### Ruby

```ruby
require 'net/http'
require 'json'
require 'uri'

def check_prompt_safety(prompt)
  uri = URI('https://localhost:3001/v2/check-prompt')

  response = Net::HTTP.post(
    uri,
    { prompt: prompt }.to_json,
    'Content-Type' => 'application/json'
  )

  JSON.parse(response.body, symbolize_names: true)
end

# Usage
result = check_prompt_safety("Help me with Ruby on Rails")

unless result[:safe]
  raise SecurityError, "Blocked [#{result[:overallSeverity]}]: #{result[:categories].join(', ')}"
end

puts "Safe to proceed!"
```

### AI Agent Pre-Processing Pattern

```javascript
// Generic pattern for any AI agent framework
async function secureAgentProcess(userMessage, agent) {
  // Step 1: Screen the input
  const securityCheck = await fetch('https://localhost:3001/v2/check-prompt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: userMessage })
  }).then(r => r.json());

  // Step 2: Only an explicit allow permits processing.
  if (securityCheck.decision !== 'allow') {
    return {
      error: 'Input was not approved for processing',
      decision: securityCheck.decision ?? 'unavailable'
    };
  }

  // Step 3: Safe to proceed
  return await agent.process(userMessage);
}
```

### Skill Installation Security Pattern

```javascript
// Scan skills before installation
async function installSkillSafely(skillPath) {
  const fs = require('fs').promises;

  // Step 1: Read the skill file
  const skillContent = await fs.readFile(skillPath, 'utf-8');

  // Step 2: Scan for security issues
  const scanResult = await fetch('https://localhost:3001/v2/scan-skill', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ skillContent })
  }).then(r => r.json());

  // Step 3: Block unsafe skills
  if (!scanResult.safe) {
    console.error(`❌ Skill installation blocked: ${scanResult.overallSeverity}`);
    console.error(`Categories: ${scanResult.categories.join(', ')}`);

    if (scanResult.skillSpecific.findings.length > 0) {
      console.error('\nSecurity findings:');
      scanResult.skillSpecific.findings.forEach(f => console.error(`  • ${f}`));
    }

    throw new Error('Skill failed security scan');
  }

  // Step 4: Safe to install
  console.log('✅ Skill passed security scan, installing...');
  await installToSkillDirectory(skillPath);
}
```


Return to the [installation guide](../README.md#installation).
