//! Decompiler Integration
//!
//! Shells out to available LLVM-based decompilers to convert LLVM IR/bitcode
//! to structured C code. Supports multiple backends with auto-detection.

use std::fs;
use std::process::Command;

/// Available decompiler backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompilerBackend {
    /// RetDec (retdec-decompiler CLI)
    RetDec,
    /// Rellic (rellic-decomp CLI)
    Rellic,
    /// LLVM C Backend Emitter (llvm-cbe)
    LlvmCbe,
    /// Built-in naive C emitter (always available)
    Builtin,
}

impl std::fmt::Display for DecompilerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompilerBackend::RetDec => write!(f, "retdec"),
            DecompilerBackend::Rellic => write!(f, "rellic"),
            DecompilerBackend::LlvmCbe => write!(f, "llvm-cbe"),
            DecompilerBackend::Builtin => write!(f, "builtin"),
        }
    }
}

/// Result of decompilation.
pub struct DecompileResult {
    pub c_code: String,
    pub backend_used: DecompilerBackend,
    pub warnings: Vec<String>,
}

/// Detect which decompiler backends are available on the system.
pub fn detect_available_backends() -> Vec<DecompilerBackend> {
    let mut available = Vec::new();

    if command_exists("retdec-decompiler") {
        available.push(DecompilerBackend::RetDec);
    }
    if command_exists("rellic-decomp") {
        available.push(DecompilerBackend::Rellic);
    }
    if command_exists("llvm-cbe") {
        available.push(DecompilerBackend::LlvmCbe);
    }

    // Built-in is always available
    available.push(DecompilerBackend::Builtin);

    available
}

/// Run decompilation on LLVM IR text, producing C code.
pub fn decompile(
    llvm_ir: &str,
    preferred_backend: Option<DecompilerBackend>,
) -> Result<DecompileResult, Box<dyn std::error::Error>> {
    let available = detect_available_backends();

    let backend = if let Some(pref) = preferred_backend {
        if available.contains(&pref) {
            pref
        } else {
            eprintln!(
                "Warning: preferred backend '{}' not available, falling back",
                pref
            );
            available[0]
        }
    } else {
        available[0]
    };

    match backend {
        DecompilerBackend::RetDec => decompile_retdec(llvm_ir),
        DecompilerBackend::Rellic => decompile_rellic(llvm_ir),
        DecompilerBackend::LlvmCbe => decompile_llvm_cbe(llvm_ir),
        DecompilerBackend::Builtin => Ok(decompile_builtin(llvm_ir)),
    }
}

/// Decompile using RetDec.
fn decompile_retdec(llvm_ir: &str) -> Result<DecompileResult, Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir().join("pvm-decompile");
    fs::create_dir_all(&tmp_dir)?;

    let ll_path = tmp_dir.join("input.ll");
    let bc_path = tmp_dir.join("input.bc");
    let out_path = tmp_dir.join("input.c");

    // Write LLVM IR
    fs::write(&ll_path, llvm_ir)?;

    // Convert .ll to .bc using llvm-as
    let llvm_as = find_llvm_tool("llvm-as");
    let status = Command::new(&llvm_as)
        .args([
            ll_path.to_str().unwrap(),
            "-o",
            bc_path.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("llvm-as failed to assemble LLVM IR".into());
    }

    // Run retdec-decompiler
    let status = Command::new("retdec-decompiler")
        .args([
            "--backend-no-opts",
            "-o",
            out_path.to_str().unwrap(),
            bc_path.to_str().unwrap(),
        ])
        .status()?;

    let mut warnings = Vec::new();
    if !status.success() {
        warnings.push("retdec-decompiler returned non-zero exit code".to_string());
    }

    let c_code = if out_path.exists() {
        fs::read_to_string(&out_path)?
    } else {
        return Err("RetDec produced no output".into());
    };

    // Cleanup
    let _ = fs::remove_dir_all(&tmp_dir);

    Ok(DecompileResult {
        c_code,
        backend_used: DecompilerBackend::RetDec,
        warnings,
    })
}

/// Decompile using Rellic.
fn decompile_rellic(llvm_ir: &str) -> Result<DecompileResult, Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir().join("pvm-decompile");
    fs::create_dir_all(&tmp_dir)?;

    let ll_path = tmp_dir.join("input.ll");
    let bc_path = tmp_dir.join("input.bc");
    let out_path = tmp_dir.join("output.c");

    fs::write(&ll_path, llvm_ir)?;

    // Convert .ll to .bc
    let llvm_as = find_llvm_tool("llvm-as");
    let status = Command::new(&llvm_as)
        .args([
            ll_path.to_str().unwrap(),
            "-o",
            bc_path.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("llvm-as failed to assemble LLVM IR".into());
    }

    // Run rellic-decomp
    let output = Command::new("rellic-decomp")
        .args([
            "--input",
            bc_path.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()?;

    let mut warnings = Vec::new();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warnings.push(format!("rellic-decomp stderr: {}", stderr));
    }

    let c_code = if out_path.exists() {
        fs::read_to_string(&out_path)?
    } else {
        return Err("Rellic produced no output".into());
    };

    let _ = fs::remove_dir_all(&tmp_dir);

    Ok(DecompileResult {
        c_code,
        backend_used: DecompilerBackend::Rellic,
        warnings,
    })
}

/// Decompile using llvm-cbe (LLVM C Backend Emitter).
fn decompile_llvm_cbe(llvm_ir: &str) -> Result<DecompileResult, Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir().join("pvm-decompile");
    fs::create_dir_all(&tmp_dir)?;

    let ll_path = tmp_dir.join("input.ll");
    let out_path = tmp_dir.join("input.cbe.c");

    fs::write(&ll_path, llvm_ir)?;

    let output = Command::new("llvm-cbe")
        .args([ll_path.to_str().unwrap()])
        .current_dir(&tmp_dir)
        .output()?;

    let mut warnings = Vec::new();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warnings.push(format!("llvm-cbe stderr: {}", stderr));
    }

    let c_code = if out_path.exists() {
        fs::read_to_string(&out_path)?
    } else {
        return Err("llvm-cbe produced no output".into());
    };

    let _ = fs::remove_dir_all(&tmp_dir);

    Ok(DecompileResult {
        c_code,
        backend_used: DecompilerBackend::LlvmCbe,
        warnings,
    })
}

/// Built-in naive C emitter that translates LLVM IR text to readable C.
/// This is a best-effort fallback when no external decompiler is available.
fn decompile_builtin(llvm_ir: &str) -> DecompileResult {
    let mut c_code = String::with_capacity(llvm_ir.len());
    let mut warnings = Vec::new();

    c_code.push_str("#include <stdint.h>\n");
    c_code.push_str("#include <stdlib.h>\n\n");
    c_code.push_str("// PVM memory model\n");
    c_code.push_str("static uint8_t pvm_memory[268435456]; // 256MB\n\n");
    c_code.push_str("// External PVM host functions\n");
    c_code.push_str("extern void pvm_ecalli(uint32_t index);\n");
    c_code.push_str("extern void pvm_trap(void) __attribute__((noreturn));\n");
    c_code.push_str("extern int64_t pvm_sbrk(int64_t size);\n\n");

    // Parse LLVM IR line by line and translate to C
    let mut in_function = false;
    let mut _func_name = String::new();
    let mut _indent = 0;

    for line in llvm_ir.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with("source_filename")
            || trimmed.starts_with("target") || trimmed.starts_with("@")
            || trimmed.starts_with("declare")
        {
            continue;
        }

        if trimmed.starts_with("define") {
            // Function definition
            in_function = true;
            _indent = 1;
            if let Some(name) = extract_func_name(trimmed) {
                _func_name = name.to_string();
                c_code.push_str(&format!("int64_t {}(void) {{\n", name));
                c_code.push_str("    int64_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;\n");
                c_code.push_str("    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = r10 = r11 = r12 = 0;\n");
            }
            continue;
        }

        if trimmed == "}" {
            in_function = false;
            c_code.push_str("}\n\n");
            continue;
        }

        if !in_function {
            continue;
        }

        // Basic block labels
        if trimmed.ends_with(':') && !trimmed.contains('=') {
            let label = trimmed.trim_end_matches(':');
            if label != "entry" {
                c_code.push_str(&format!("{}:\n", label));
            }
            continue;
        }

        // Translate LLVM instructions to C (best effort)
        if let Some(c_line) = translate_llvm_to_c(trimmed) {
            c_code.push_str(&format!("    {};\n", c_line));
        }
    }

    warnings.push("Used built-in naive C emitter (install retdec or rellic for better results)".to_string());

    DecompileResult {
        c_code,
        backend_used: DecompilerBackend::Builtin,
        warnings,
    }
}

/// Translate a single LLVM IR instruction to C (best effort).
fn translate_llvm_to_c(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Store: store i64 VALUE, ptr %rN
    if trimmed.starts_with("store") {
        if let Some(c) = parse_store(trimmed) {
            return Some(c);
        }
        return None;
    }

    // Branch
    if trimmed.starts_with("br label") {
        if let Some(label) = trimmed.strip_prefix("br label %") {
            return Some(format!("goto {}", label));
        }
    }

    if trimmed.starts_with("br i1") {
        return parse_conditional_branch(trimmed);
    }

    // Return
    if trimmed.starts_with("ret i64") {
        let val = trimmed.strip_prefix("ret i64 ").unwrap_or("r0");
        return Some(format!("return {}", val));
    }

    // Unreachable
    if trimmed == "unreachable" {
        return Some("__builtin_unreachable()".to_string());
    }

    // Call to pvm_trap
    if trimmed.contains("call void @pvm_trap") {
        return Some("pvm_trap()".to_string());
    }

    // Call to pvm_ecalli
    if trimmed.contains("call void @pvm_ecalli") {
        if let Some(idx) = extract_call_arg(trimmed) {
            return Some(format!("pvm_ecalli({})", idx));
        }
    }

    // Switch
    if trimmed.starts_with("switch") {
        return Some("/* switch statement */".to_string());
    }

    // Most other instructions are SSA temporaries that get folded
    // The C emitter doesn't need to handle them since they're intermediate
    None
}

/// Parse an LLVM store instruction into C.
fn parse_store(line: &str) -> Option<String> {
    // store i64 VALUE, ptr %rN
    // We care about stores to register allocas
    if let Some(rest) = line.strip_prefix("store ") {
        let parts: Vec<&str> = rest.split(", ptr ").collect();
        if parts.len() == 2 {
            let val_part = parts[0]; // "i64 VALUE"
            let ptr_part = parts[1].trim_end_matches(", align 8"); // "%rN"

            if ptr_part.starts_with("%r") {
                let reg = ptr_part.trim_start_matches('%');
                let val = val_part.split_whitespace().last()?;
                return Some(format!("{} = {}", reg, val));
            }
        }
    }
    None
}

/// Parse a conditional branch into C.
fn parse_conditional_branch(line: &str) -> Option<String> {
    // br i1 %tN, label %THEN, label %ELSE
    let parts: Vec<&str> = line.split(", label %").collect();
    if parts.len() >= 3 {
        let then_label = parts[1];
        let else_label = parts[2];
        return Some(format!(
            "if (...) goto {}; else goto {}",
            then_label, else_label
        ));
    }
    None
}

/// Extract function name from LLVM define line.
fn extract_func_name(line: &str) -> Option<&str> {
    // define i64 @NAME() {
    let at = line.find('@')?;
    let after_at = &line[at + 1..];
    let paren = after_at.find('(')?;
    Some(&after_at[..paren])
}

/// Extract call argument.
fn extract_call_arg(line: &str) -> Option<&str> {
    let paren = line.find('(')?;
    let close = line.find(')')?;
    let arg_part = &line[paren + 1..close];
    // "i32 VALUE" -> VALUE
    arg_part.split_whitespace().last()
}

/// Check if a command exists on PATH.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find an LLVM tool, trying versioned names first.
fn find_llvm_tool(name: &str) -> String {
    // Try versioned names (e.g., llvm-as-17, llvm-as-16, etc.)
    for version in (14..=19).rev() {
        let versioned = format!("{}-{}", name, version);
        if command_exists(&versioned) {
            return versioned;
        }
    }
    // Fall back to unversioned
    name.to_string()
}
