//! LLM Refinement Harness
//!
//! Implements a multi-round DeGPT/D-LiFT style refinement loop using the local
//! `claude` CLI. Three roles cooperate to improve decompiled C:
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

    call_claude(&prompt)
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

    call_claude(&prompt)
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

    let response = call_claude(&prompt)?;

    // Extract code block from response
    extract_code_block(&response).ok_or_else(|| "Failed to extract code from LLM response".into())
}

/// Call the local claude CLI with a prompt.
fn call_claude(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Try 'claude' CLI first
    // Remove CLAUDECODE env var so child process doesn't think it's a nested session
    let result = Command::new("claude")
        .args(["--print", "--no-input", "--prompt", prompt])
        .env_remove("CLAUDECODE")
        .output();

    match result {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
        _ => {
            // Fallback: try with -p flag (older versions)
            let result = Command::new("claude")
                .args(["-p", prompt])
                .env_remove("CLAUDECODE")
                .output();

            match result {
                Ok(output) if output.status.success() => {
                    Ok(String::from_utf8_lossy(&output.stdout).to_string())
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("claude CLI failed: {}", stderr).into())
                }
                Err(e) => {
                    Err(format!(
                        "claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code\nError: {}",
                        e
                    ).into())
                }
            }
        }
    }
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
        Some(response.trim().to_string())
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

    let response = call_claude(&prompt)?;
    extract_code_block(&response).ok_or_else(|| {
        format!(
            "Failed to extract pseudo-code from LLM response for {}",
            fn_name
        )
        .into()
    })
}

/// Check if the claude CLI is available.
pub fn is_claude_available() -> bool {
    Command::new("claude")
        .arg("--version")
        .env_remove("CLAUDECODE")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
