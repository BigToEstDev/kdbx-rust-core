//! The rated password across the boundary.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{ok_payload, prepare};

fn call(command: &str, args: Value) -> String {
    run_with_bytes(command, &args.to_string(), None).envelope
}

#[test]
fn a_generated_password_comes_with_its_own_rating() {
    prepare();

    let envelope = call(
        "analyzed_password",
        json!({
            "length": 24,
            "numbers": true,
            "lowercase_letters": true,
            "uppercase_letters": true,
            "symbols": true,
            "spaces": false,
            "exclude_similar_characters": true,
            "strict": true,
        }),
    );
    assert_shape("analyzed_password", &envelope);

    let analyzed = ok_payload(&envelope);
    assert_eq!(
        analyzed["password"].as_str().map(str::len),
        Some(24),
        "{}",
        analyzed
    );
    assert!(
        !analyzed["score"].is_null(),
        "the rating belongs to this password, which is why it comes with it: {}",
        analyzed
    );
}
