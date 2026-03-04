//! LLM Refinement Harness
//!
//! Implements a multi-round DeGPT/D-LiFT style refinement loop using
//! OpenRouter's API. Three roles cooperate to improve decompiled C:
//!   - **Referee**: Evaluates code quality and identifies issues
//!   - **Advisor**: Suggests specific improvements (naming, comments, structure)
//!   - **Operator**: Applies improvements while preserving semantics

use std::process::Command;

/// Maximum refinement rounds.
const MAX_ROUNDS: usize = 3;

/// Result of LLM refinement.
pub struct RefinementResult {
    pub refined_code: String,
    pub rounds_completed: usize,
    pub improvements: Vec<String>,
    pub raw_decompiler_output: String,
}

/// Run the full LLM refinement pipeline on decompiled C code.
pub fn refine(c_code: &str, context: &str) -> Result<RefinementResult, Box<dyn std::error::Error>> {
    let mut current = c_code.to_string();
    let mut all_improvements = Vec::new();
    let raw = c_code.to_string();

    for round in 0..MAX_ROUNDS {
        eprintln!("  LLM refinement round {}/{}...", round + 1, MAX_ROUNDS);

        // Step 1: Referee evaluates
        let evaluation = run_referee(&current, context)?;

        // If the referee says it's good enough, stop
        if evaluation.contains("NO_ISSUES_FOUND") || evaluation.contains("QUALITY: EXCELLENT") {
            eprintln!("  Referee: code quality is excellent, stopping refinement");
            break;
        }

        // Step 2: Advisor suggests improvements
        let suggestions = run_advisor(&current, &evaluation, context)?;

        // Step 3: Operator applies improvements
        let improved = run_operator(&current, &suggestions, context)?;

        // Validate the improvement isn't empty or obviously broken
        if improved.len() > 20 && improved.contains("int") {
            all_improvements.push(format!("Round {}: {}", round + 1, summarize(&suggestions)));
            current = improved;
        } else {
            eprintln!(
                "  Warning: LLM produced invalid output in round {}, keeping previous",
                round + 1
            );
            break;
        }
    }

    Ok(RefinementResult {
        refined_code: current,
        rounds_completed: all_improvements.len(),
        improvements: all_improvements,
        raw_decompiler_output: raw,
    })
}

/// Run the Referee role: evaluate code quality.
fn run_referee(code: &str, context: &str) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        r#"You are a code quality referee for decompiled PVM (Polkadot Virtual Machine) bytecode.

Context: {}

Evaluate this decompiled C code for:
1. Variable naming quality (are names meaningful or still register-like?)
2. Comment coverage (are complex operations explained?)
3. Control flow clarity (are loops/conditions readable?)
4. Type accuracy (are types appropriate for the operations?)
5. Overall readability

If the code is already high quality, respond with exactly "QUALITY: EXCELLENT" and "NO_ISSUES_FOUND".
Otherwise, list specific issues, one per line, prefixed with [NAMING], [COMMENT], [FLOW], [TYPE], or [READABILITY].

Code to evaluate:
```c
{}
```"#,
        context, code
    );

    call_llm(&prompt)
}

/// Run the Advisor role: suggest specific improvements.
fn run_advisor(
    code: &str,
    evaluation: &str,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        r#"You are a code improvement advisor for decompiled PVM (Polkadot Virtual Machine) bytecode.

Context: {}

A referee has identified these issues in the decompiled code:
{}

For each issue, suggest a specific fix. Be concrete:
- For naming: suggest the exact new name and why
- For comments: write the exact comment to add
- For flow: describe the structural change
- For types: specify the correct type

Keep suggestions that preserve the code's EXACT semantics. Do not change logic.

Code:
```c
{}
```

Respond with numbered suggestions, one per line."#,
        context, evaluation, code
    );

    call_llm(&prompt)
}

/// Run the Operator role: apply improvements to code.
fn run_operator(
    code: &str,
    suggestions: &str,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        r#"You are a code operator. Apply the following improvements to this decompiled PVM code.

Context: {}

CRITICAL RULES:
1. Preserve EXACT semantics - do not change any logic, control flow, or computation
2. Only improve naming, comments, types, and formatting
3. Keep all memory accesses, arithmetic, and control flow identical
4. Output ONLY the improved C code, no explanations

Improvements to apply:
{}

Original code:
```c
{}
```

Output the improved C code only, wrapped in ```c ... ```."#,
        context, suggestions, code
    );

    let response = call_llm(&prompt)?;

    // Extract code block from response
    extract_code_block(&response).ok_or_else(|| "Failed to extract code from LLM response".into())
}

/// Load the OpenRouter API key from .env file or environment.
fn get_api_key() -> Result<String, Box<dyn std::error::Error>> {
    // Check environment first
    if let Ok(key) = std::env::var("OPENROUTER_API_KEY") {
        if !key.is_empty() {
            return Ok(key);
        }
    }

    // Try loading from .env in the current directory or ancestors
    let mut dir = std::env::current_dir()?;
    loop {
        let env_path = dir.join(".env");
        if env_path.exists() {
            let content = std::fs::read_to_string(&env_path)?;
            for line in content.lines() {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("OPENROUTER_API_KEY=") {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() {
                        return Ok(val.to_string());
                    }
                }
            }
        }
        if !dir.pop() {
            break;
        }
    }

    Err("OPENROUTER_API_KEY not found. Set it in environment or .env file.".into())
}

/// Call OpenRouter API with a prompt.
fn call_llm(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let api_key = get_api_key()?;

    // Build JSON payload - escape the prompt for JSON
    let escaped_prompt = prompt
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");

    let json_body = format!(
        r#"{{"model":"google/gemini-3.1-flash-lite-preview","messages":[{{"role":"user","content":"{}"}}]}}"#,
        escaped_prompt
    );

    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "https://openrouter.ai/api/v1/chat/completions",
            "-H",
            &format!("Authorization: Bearer {}", api_key),
            "-H",
            "Content-Type: application/json",
            "-d",
            &json_body,
        ])
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", stderr).into());
    }

    let body = String::from_utf8_lossy(&output.stdout);

    // Parse the response JSON to extract the message content.
    // We do minimal JSON parsing to avoid adding a dependency.
    extract_openrouter_content(&body)
        .ok_or_else(|| format!("Failed to parse OpenRouter response: {}", body).into())
}

/// Extract the assistant message content from an OpenRouter JSON response.
fn extract_openrouter_content(json: &str) -> Option<String> {
    // Look for "content":"..." in the response
    // The response format is: {"choices":[{"message":{"content":"..."}}]}
    let marker = r#""content":""#;
    let start = json.find(marker)? + marker.len();
    let rest = &json[start..];

    // Find the closing quote, handling escaped quotes
    let mut result = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '\\' => match chars.next()? {
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                '/' => result.push('/'),
                'u' => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(cp) {
                            result.push(c);
                        }
                    }
                }
                other => {
                    result.push('\\');
                    result.push(other);
                }
            },
            '"' => break,
            c => result.push(c),
        }
    }

    Some(result)
}

/// Extract a code block from an LLM response.
fn extract_code_block(response: &str) -> Option<String> {
    // Try to find ```c ... ``` block
    if let Some(start) = response.find("```c") {
        let code_start = start + 4;
        if let Some(end) = response[code_start..].find("```") {
            return Some(response[code_start..code_start + end].trim().to_string());
        }
    }

    // Try plain ``` block
    if let Some(start) = response.find("```") {
        let code_start = start + 3;
        // Skip optional language tag on same line
        let code_start = if let Some(nl) = response[code_start..].find('\n') {
            code_start + nl + 1
        } else {
            code_start
        };
        if let Some(end) = response[code_start..].find("```") {
            return Some(response[code_start..code_start + end].trim().to_string());
        }
    }

    // If no code block, return the whole response if it looks like code
    if (response.contains("int") || response.contains("fn ")) && response.contains("{") {
        // Strip any stray leading/trailing backtick fences
        let cleaned: String = response
            .lines()
            .filter(|l| !l.trim().starts_with("```"))
            .collect::<Vec<_>>()
            .join("\n");
        Some(cleaned.trim().to_string())
    } else {
        None
    }
}

/// Summarize suggestions to a one-line description.
fn summarize(suggestions: &str) -> String {
    let lines: Vec<&str> = suggestions
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lines.len() <= 2 {
        lines.join("; ")
    } else {
        format!("{} improvements applied", lines.len())
    }
}

/// Refine a single function's pseudo-code via a single LLM call.
///
/// Asks the LLM to add explanatory comments and improve variable names
/// while preserving the exact structure and syntax.
pub fn refine_pseudo_code(
    pseudo_code: &str,
    fn_name: &str,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        r#"You are enhancing decompiled PVM (Polkadot Virtual Machine) pseudo-code.

Context: {context}
Function: {fn_name}

RULES:
1. Add short explanatory comments for non-obvious operations (memory accesses, bitwise ops, constants)
2. Rename variables to meaningful names based on their usage patterns (e.g. ptr_0_56 → counter, var_1 → switch_index)
3. Do NOT change any logic, control flow, operators, or expressions
4. Keep the exact same syntax — this is pseudo-code, not C or Rust
5. Preserve function signature exactly
6. Output ONLY the improved pseudo-code in a fenced code block

Pseudo-code to enhance:
```
{pseudo_code}
```"#
    );

    let response = call_llm(&prompt)?;
    extract_code_block(&response).ok_or_else(|| {
        format!(
            "Failed to extract pseudo-code from LLM response for {}",
            fn_name
        )
        .into()
    })
}

/// Check if the OpenRouter API is available (key is configured).
pub fn is_llm_available() -> bool {
    get_api_key().is_ok()
}
