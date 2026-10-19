use serde_json::{Map, Value};

/// 递归排序对象键，用于 CPVC control_mac 输入。
pub fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                let v = map.get(&k).cloned().unwrap_or(Value::Null);
                out.insert(k, canonicalize(v));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let canon = canonicalize(value.clone());
    serde_json::to_vec(&canon).unwrap_or_default()
}
