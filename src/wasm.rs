use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Decompile a PVM binary blob to pseudo-code.
///
/// Accepts raw bytes (Uint8Array) of a PVM binary in SPI format,
/// raw blob format, or with metadata prefix. Returns pseudo-code as a string.
#[wasm_bindgen]
pub fn decompile(bytes: &[u8]) -> Result<String, JsValue> {
    crate::decompile_to_pseudocode(bytes)
        .map(|out| out.pseudo_code)
        .map_err(|e| JsValue::from_str(&e))
}

/// Decompile a PVM binary blob and return structured metadata as JSON.
///
/// Returns a JSON string with the following structure:
/// ```json
/// {
///   "pseudo_code": "fn main(...) { ... }",
///   "function_count": 5,
///   "functions": [
///     { "name": "main", "entry_pc": 0, "block_count": 3, "param_count": 2 }
///   ],
///   "warnings": ["Unknown opcode 0xfe: 1 occurrence(s)"]
/// }
/// ```
#[wasm_bindgen]
pub fn decompile_with_metadata(bytes: &[u8]) -> Result<String, JsValue> {
    let output = crate::decompile_to_pseudocode(bytes).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("JSON serialization error: {}", e)))
}

// Note: wasm_bindgen types (JsValue) cannot be tested natively.
// The underlying logic is tested via lib_tests::test_decompile_to_pseudocode_*.
// For actual WASM integration tests, use `wasm-pack test --headless --chrome`.
