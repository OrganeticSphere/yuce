//! RFC 8785 (JSON Canonicalization Scheme) serializer for the subset of JSON used by SBGK
//! (no floating point numbers: integers only).

use serde_json::Value;

pub fn to_jcs(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                // The kernel never emits non-integers; keep a deterministic fallback.
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string escape")),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            // RFC 8785 §3.2.3: sort by UTF-16 code units.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key escape"));
                out.push(':');
                write_value(&m[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_is_compact() {
        let v = json!({"b": 1, "a": [true, null, "x"], "\u{10000}": 2, "\u{ffff}": 3});
        // U+FFFF sorts before U+10000 (surrogate pair D800..) in UTF-16 order? No: 0xFFFF > 0xD800.
        let s = to_jcs(&v);
        assert!(s.starts_with("{\"a\":[true,null,\"x\"],\"b\":1,"));
        let p_ffff = s.find('\u{ffff}').unwrap();
        let p_10000 = s.find('\u{10000}').unwrap();
        assert!(p_10000 < p_ffff, "UTF-16 order puts supplementary chars before U+FFFF");
    }

    #[test]
    fn insertion_order_irrelevant() {
        let a: Value = serde_json::from_str(r#"{"x":1,"y":{"b":2,"a":1}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{ "y" : {"a":1, "b":2}, "x":1 }"#).unwrap();
        assert_eq!(to_jcs(&a), to_jcs(&b));
    }
}
