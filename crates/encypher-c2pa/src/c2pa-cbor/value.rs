//! CBOR data model preserving byte-string/text distinction and map order.

/// A CBOR value. Unlike `serde_json::Value`, this distinguishes byte strings
/// from text strings and preserves map entry order — both required for C2PA
/// byte-parity and hash bindings.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Unsigned or negative integer (major types 0 and 1).
    Integer(i128),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3).
    Text(String),
    /// Array (major type 4).
    Array(Vec<Value>),
    /// Map (major type 5), order preserved.
    Map(Vec<(Value, Value)>),
    /// Tagged value (major type 6).
    Tag(u64, Box<Value>),
    /// Boolean (major type 7).
    Bool(bool),
    /// Null (major type 7).
    Null,
    /// 64-bit float (major type 7).
    Float(f64),
}

impl Value {
    /// Borrow as a text string slice if this is [`Value::Text`].
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Borrow as bytes if this is [`Value::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Borrow as map entries if this is [`Value::Map`].
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Look up a value by text key in a [`Value::Map`].
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<i128> for Value {
    fn from(n: i128) -> Self {
        Value::Integer(n)
    }
}
