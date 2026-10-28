// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Bounded AMF3 metadata traversal.
//!
//! AMF3 has independent string, object, and trait reference tables. Metadata
//! values that are irrelevant to C2PA still have to update those tables so a
//! later C2PA pair can use a reference created while the earlier value was
//! skipped.

use std::str;

use super::ErtmpWireError;

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 1_000_000;
const MAX_REFERENCES_PER_TABLE: usize = 65_536;
const MAX_COLLECTION_ENTRIES: usize = MAX_NODES;

const C2PA_MANIFEST: &str = "c2paManifest";
const C2PA_SEGMENT_INFO: &str = "c2paSegmentInfo";

/// Visits the C2PA metadata pairs in one AMF3 Metadata packet.
///
/// The packet is an alternating sequence of AMF3 String names and AMF3
/// values. Unrecognized values are parsed rather than treated as opaque bytes,
/// because their strings, objects, and traits can be referenced by later
/// values. Only native ByteArray values belonging to the two C2PA names are
/// emitted.
pub(super) fn for_each_metadata_pair(
    bytes: &[u8],
    max_pairs: usize,
    max_value_bytes: usize,
    mut emit: impl FnMut(&str, &[u8]) -> Result<(), super::ErtmpWireError>,
) -> Result<(), super::ErtmpWireError> {
    if bytes.is_empty() {
        return Err(ErtmpWireError::new("empty AMF3 metadata body"));
    }

    let mut decoder = Decoder::new(bytes);
    let mut emitted_pairs = 0usize;
    let mut emitted_value_bytes = 0usize;

    while !decoder.is_empty() {
        let marker = decoder.read_byte()?;
        if marker != 0x06 {
            return Err(ErtmpWireError::new("AMF3 metadata name is not a String"));
        }
        let name = decoder.read_string()?;
        if decoder.is_empty() {
            return Err(ErtmpWireError::new(
                "AMF3 metadata name has no following value",
            ));
        }

        let value = decoder.read_value(0)?;
        if name != C2PA_MANIFEST && name != C2PA_SEGMENT_INFO {
            continue;
        }
        let Value::ByteArray(value) = value else {
            return Err(ErtmpWireError::new(format!(
                "AMF3 metadata value for {name} is not a ByteArray"
            )));
        };

        if emitted_pairs >= max_pairs {
            return Err(ErtmpWireError::new(
                "AMF3 emitted metadata pair count exceeds its limit",
            ));
        }
        let next_value_bytes = emitted_value_bytes
            .checked_add(value.len())
            .ok_or_else(|| ErtmpWireError::new("AMF3 emitted metadata byte count overflow"))?;
        if next_value_bytes > max_value_bytes {
            return Err(ErtmpWireError::new(
                "AMF3 emitted metadata bytes exceed their limit",
            ));
        }

        // Both budgets are checked before the callback can copy the borrowed
        // value into an owned verifier event.
        emit(name, value)?;
        emitted_pairs += 1;
        emitted_value_bytes = next_value_bytes;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectKind {
    XmlDocument,
    Date,
    Array,
    Object,
    Xml,
    ByteArray,
    VectorInt,
    VectorUint,
    VectorDouble,
    VectorObject,
    Dictionary,
}

#[derive(Clone, Copy)]
struct ObjectReference<'a> {
    kind: ObjectKind,
    byte_array: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
struct TraitReference<'a> {
    class_name: &'a str,
    externalizable: bool,
    dynamic: bool,
    sealed_count: usize,
}

#[derive(Clone, Copy)]
enum Value<'a> {
    ByteArray(&'a [u8]),
    Other,
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    strings: Vec<&'a str>,
    objects: Vec<ObjectReference<'a>>,
    traits: Vec<TraitReference<'a>>,
    nodes: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            strings: Vec::new(),
            objects: Vec::new(),
            traits: Vec::new(),
            nodes: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_value(&mut self, depth: usize) -> Result<Value<'a>, ErtmpWireError> {
        if depth > MAX_DEPTH {
            return Err(ErtmpWireError::new("AMF3 value nesting exceeds its limit"));
        }
        self.add_nodes(1)?;

        match self.read_byte()? {
            0x00..=0x03 => Ok(Value::Other),
            0x04 => {
                self.read_u29()?;
                Ok(Value::Other)
            }
            0x05 => {
                self.take(8)?;
                Ok(Value::Other)
            }
            0x06 => {
                self.read_string()?;
                Ok(Value::Other)
            }
            0x07 => self.read_xml_like(ObjectKind::XmlDocument),
            0x08 => self.read_date(),
            0x09 => self.read_array(depth),
            0x0a => self.read_object(depth),
            0x0b => self.read_xml_like(ObjectKind::Xml),
            0x0c => self.read_byte_array(),
            0x0d => self.read_primitive_vector(ObjectKind::VectorInt, 4),
            0x0e => self.read_primitive_vector(ObjectKind::VectorUint, 4),
            0x0f => self.read_primitive_vector(ObjectKind::VectorDouble, 8),
            0x10 => self.read_object_vector(depth),
            0x11 => self.read_dictionary(depth),
            marker => Err(ErtmpWireError::new(format!(
                "unknown AMF3 type marker 0x{marker:02x}"
            ))),
        }
    }

    fn read_xml_like(&mut self, kind: ObjectKind) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, kind)?;
            return Ok(Value::Other);
        }

        let length = self.inline_count(header, "AMF3 XML byte length")?;
        let value = self.take(length)?;
        str::from_utf8(value).map_err(|_| ErtmpWireError::new("AMF3 XML value is not UTF-8"))?;
        self.push_object(ObjectReference {
            kind,
            byte_array: None,
        })?;
        Ok(Value::Other)
    }

    fn read_date(&mut self) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, ObjectKind::Date)?;
            return Ok(Value::Other);
        }
        if header != 1 {
            return Err(ErtmpWireError::new(
                "AMF3 inline Date header has reserved bits set",
            ));
        }

        self.take(8)?;
        self.push_object(ObjectReference {
            kind: ObjectKind::Date,
            byte_array: None,
        })?;
        Ok(Value::Other)
    }

    fn read_array(&mut self, depth: usize) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, ObjectKind::Array)?;
            return Ok(Value::Other);
        }

        let dense_count = self.collection_count(header, "AMF3 Array dense item count")?;
        self.push_object(ObjectReference {
            kind: ObjectKind::Array,
            byte_array: None,
        })?;

        loop {
            let name = self.read_string()?;
            if name.is_empty() {
                break;
            }
            self.read_value(depth + 1)?;
        }
        for _ in 0..dense_count {
            self.read_value(depth + 1)?;
        }
        Ok(Value::Other)
    }

    fn read_object(&mut self, depth: usize) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, ObjectKind::Object)?;
            return Ok(Value::Other);
        }

        let traits = if header & 2 == 0 {
            let index = usize::try_from(header >> 2)
                .map_err(|_| ErtmpWireError::new("AMF3 trait reference index overflow"))?;
            *self
                .traits
                .get(index)
                .ok_or_else(|| ErtmpWireError::new("invalid AMF3 trait reference"))?
        } else {
            let sealed_count = usize::try_from(header >> 4)
                .map_err(|_| ErtmpWireError::new("AMF3 sealed member count overflow"))?;
            self.check_collection_count(sealed_count, "AMF3 sealed member count")?;
            let externalizable = header & 4 != 0;
            let dynamic = header & 8 != 0;
            if externalizable && (dynamic || sealed_count != 0) {
                return Err(ErtmpWireError::new(
                    "invalid AMF3 externalizable trait flags",
                ));
            }
            let class_name = self.read_string()?;
            let traits = TraitReference {
                class_name,
                externalizable,
                dynamic,
                sealed_count,
            };
            self.push_trait(traits)?;
            for _ in 0..sealed_count {
                self.read_string()?;
            }
            traits
        };

        // Object references can occur in the object's own member values, so
        // install the object before walking those values.
        self.push_object(ObjectReference {
            kind: ObjectKind::Object,
            byte_array: None,
        })?;

        if traits.externalizable {
            let class = if traits.class_name.is_empty() {
                "<anonymous>"
            } else {
                traits.class_name
            };
            return Err(ErtmpWireError::new(format!(
                "AMF3 externalizable class {class} has indeterminate framing"
            )));
        }

        for _ in 0..traits.sealed_count {
            self.read_value(depth + 1)?;
        }
        if traits.dynamic {
            loop {
                let name = self.read_string()?;
                if name.is_empty() {
                    break;
                }
                self.read_value(depth + 1)?;
            }
        }
        Ok(Value::Other)
    }

    fn read_byte_array(&mut self) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            let reference = self.object_reference(header, ObjectKind::ByteArray)?;
            return Ok(Value::ByteArray(reference.byte_array.ok_or_else(|| {
                ErtmpWireError::new("AMF3 ByteArray reference has no byte payload")
            })?));
        }

        let length = self.inline_count(header, "AMF3 ByteArray length")?;
        let value = self.take(length)?;
        self.push_object(ObjectReference {
            kind: ObjectKind::ByteArray,
            byte_array: Some(value),
        })?;
        Ok(Value::ByteArray(value))
    }

    fn read_primitive_vector(
        &mut self,
        kind: ObjectKind,
        item_width: usize,
    ) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, kind)?;
            return Ok(Value::Other);
        }

        let count = self.collection_count(header, "AMF3 Vector item count")?;
        self.read_boolean_byte("AMF3 Vector fixed flag")?;
        self.push_object(ObjectReference {
            kind,
            byte_array: None,
        })?;
        self.add_nodes(count)?;
        let byte_length = count
            .checked_mul(item_width)
            .ok_or_else(|| ErtmpWireError::new("AMF3 Vector byte length overflow"))?;
        self.take(byte_length)?;
        Ok(Value::Other)
    }

    fn read_object_vector(&mut self, depth: usize) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, ObjectKind::VectorObject)?;
            return Ok(Value::Other);
        }

        let count = self.collection_count(header, "AMF3 Vector item count")?;
        self.read_boolean_byte("AMF3 Vector fixed flag")?;
        self.read_string()?;
        self.push_object(ObjectReference {
            kind: ObjectKind::VectorObject,
            byte_array: None,
        })?;
        for _ in 0..count {
            self.read_value(depth + 1)?;
        }
        Ok(Value::Other)
    }

    fn read_dictionary(&mut self, depth: usize) -> Result<Value<'a>, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            self.object_reference(header, ObjectKind::Dictionary)?;
            return Ok(Value::Other);
        }

        let count = self.collection_count(header, "AMF3 Dictionary entry count")?;
        self.read_boolean_byte("AMF3 Dictionary weak-keys flag")?;
        self.push_object(ObjectReference {
            kind: ObjectKind::Dictionary,
            byte_array: None,
        })?;
        for _ in 0..count {
            self.read_value(depth + 1)?;
            self.read_value(depth + 1)?;
        }
        Ok(Value::Other)
    }

    fn read_string(&mut self) -> Result<&'a str, ErtmpWireError> {
        let header = self.read_u29()?;
        if header & 1 == 0 {
            let index = usize::try_from(header >> 1)
                .map_err(|_| ErtmpWireError::new("AMF3 string reference index overflow"))?;
            return self
                .strings
                .get(index)
                .copied()
                .ok_or_else(|| ErtmpWireError::new("invalid AMF3 string reference"));
        }

        let length = self.inline_count(header, "AMF3 String length")?;
        let value = str::from_utf8(self.take(length)?)
            .map_err(|_| ErtmpWireError::new("AMF3 String is not UTF-8"))?;
        // The AMF3 empty string is never entered in the reference table.
        if !value.is_empty() {
            self.push_string(value)?;
        }
        Ok(value)
    }

    fn object_reference(
        &self,
        header: u32,
        expected: ObjectKind,
    ) -> Result<ObjectReference<'a>, ErtmpWireError> {
        let index = usize::try_from(header >> 1)
            .map_err(|_| ErtmpWireError::new("AMF3 object reference index overflow"))?;
        let reference = *self
            .objects
            .get(index)
            .ok_or_else(|| ErtmpWireError::new("invalid AMF3 object reference"))?;
        if reference.kind != expected {
            return Err(ErtmpWireError::new(format!(
                "AMF3 object reference type mismatch: expected {expected:?}, found {:?}",
                reference.kind
            )));
        }
        Ok(reference)
    }

    fn collection_count(&self, header: u32, label: &str) -> Result<usize, ErtmpWireError> {
        let count = self.inline_count(header, label)?;
        self.check_collection_count(count, label)?;
        Ok(count)
    }

    fn inline_count(&self, header: u32, label: &str) -> Result<usize, ErtmpWireError> {
        usize::try_from(header >> 1)
            .map_err(|_| ErtmpWireError::new(format!("{label} overflows usize")))
    }

    fn check_collection_count(&self, count: usize, label: &str) -> Result<(), ErtmpWireError> {
        if count > MAX_COLLECTION_ENTRIES {
            return Err(ErtmpWireError::new(format!("{label} exceeds its limit")));
        }
        Ok(())
    }

    fn add_nodes(&mut self, count: usize) -> Result<(), ErtmpWireError> {
        let nodes = self
            .nodes
            .checked_add(count)
            .ok_or_else(|| ErtmpWireError::new("AMF3 node count overflow"))?;
        if nodes > MAX_NODES {
            return Err(ErtmpWireError::new("AMF3 node count exceeds its limit"));
        }
        self.nodes = nodes;
        Ok(())
    }

    fn push_string(&mut self, value: &'a str) -> Result<(), ErtmpWireError> {
        if self.strings.len() >= MAX_REFERENCES_PER_TABLE {
            return Err(ErtmpWireError::new(
                "AMF3 string reference table exceeds its limit",
            ));
        }
        self.strings
            .try_reserve(1)
            .map_err(|_| ErtmpWireError::new("cannot allocate AMF3 string reference table"))?;
        self.strings.push(value);
        Ok(())
    }

    fn push_object(&mut self, value: ObjectReference<'a>) -> Result<(), ErtmpWireError> {
        if self.objects.len() >= MAX_REFERENCES_PER_TABLE {
            return Err(ErtmpWireError::new(
                "AMF3 object reference table exceeds its limit",
            ));
        }
        self.objects
            .try_reserve(1)
            .map_err(|_| ErtmpWireError::new("cannot allocate AMF3 object reference table"))?;
        self.objects.push(value);
        Ok(())
    }

    fn push_trait(&mut self, value: TraitReference<'a>) -> Result<(), ErtmpWireError> {
        if self.traits.len() >= MAX_REFERENCES_PER_TABLE {
            return Err(ErtmpWireError::new(
                "AMF3 trait reference table exceeds its limit",
            ));
        }
        self.traits
            .try_reserve(1)
            .map_err(|_| ErtmpWireError::new("cannot allocate AMF3 trait reference table"))?;
        self.traits.push(value);
        Ok(())
    }

    fn read_boolean_byte(&mut self, label: &str) -> Result<bool, ErtmpWireError> {
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ErtmpWireError::new(format!("invalid {label}"))),
        }
    }

    fn read_u29(&mut self) -> Result<u32, ErtmpWireError> {
        let mut value = 0u32;
        for index in 0..4 {
            let byte = self
                .read_byte()
                .map_err(|_| ErtmpWireError::new("truncated AMF3 variable-length integer"))?;
            if index == 3 {
                return Ok((value << 8) | u32::from(byte));
            }
            value = (value << 7) | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        unreachable!("the fourth AMF3 U29 byte always terminates the integer")
    }

    fn read_byte(&mut self) -> Result<u8, ErtmpWireError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| ErtmpWireError::new("truncated AMF3 value"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ErtmpWireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| ErtmpWireError::new("AMF3 byte range overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ErtmpWireError::new("truncated AMF3 value"))?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u29(value: u32) -> Vec<u8> {
        assert!(value <= 0x1fff_ffff);
        if value < 0x80 {
            vec![value as u8]
        } else if value < 0x4000 {
            vec![((value >> 7) as u8) | 0x80, (value & 0x7f) as u8]
        } else if value < 0x20_0000 {
            vec![
                ((value >> 14) as u8) | 0x80,
                (((value >> 7) & 0x7f) as u8) | 0x80,
                (value & 0x7f) as u8,
            ]
        } else {
            vec![
                ((value >> 22) as u8) | 0x80,
                (((value >> 15) & 0x7f) as u8) | 0x80,
                (((value >> 8) & 0x7f) as u8) | 0x80,
                (value & 0xff) as u8,
            ]
        }
    }

    fn inline_string(value: &str) -> Vec<u8> {
        let mut bytes = u29((value.len() as u32) << 1 | 1);
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    fn name(value: &str) -> Vec<u8> {
        let mut bytes = vec![0x06];
        bytes.extend(inline_string(value));
        bytes
    }

    fn byte_array(value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x0c];
        bytes.extend(u29((value.len() as u32) << 1 | 1));
        bytes.extend_from_slice(value);
        bytes
    }

    fn collect(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ErtmpWireError> {
        let mut values = Vec::new();
        for_each_metadata_pair(bytes, 16, 1024, |name, value| {
            values.push((name.to_owned(), value.to_vec()));
            Ok(())
        })?;
        Ok(values)
    }

    #[test]
    fn mixed_metadata_skips_undefined_and_structured_values() {
        let mut bytes = name("colorInfo");
        bytes.push(0x00);

        bytes.extend(name("structured"));
        bytes.push(0x0a);
        bytes.extend(u29(0x13)); // inline object and traits, one sealed member
        bytes.extend(inline_string(""));
        bytes.extend(inline_string("self"));
        bytes.push(0x0a);
        bytes.extend(u29(0)); // reference the object while it is being decoded

        bytes.extend(name(C2PA_SEGMENT_INFO));
        bytes.extend(byte_array(b"segment"));
        bytes.extend(name("ignoredAfter"));
        bytes.push(0x03);
        bytes.extend(name(C2PA_MANIFEST));
        bytes.extend(byte_array(b"manifest"));

        assert_eq!(
            collect(&bytes).unwrap(),
            vec![
                (C2PA_SEGMENT_INFO.to_owned(), b"segment".to_vec()),
                (C2PA_MANIFEST.to_owned(), b"manifest".to_vec()),
            ]
        );
    }

    #[test]
    fn string_byte_array_and_trait_references_remain_usable() {
        let mut bytes = name("objectOne");
        bytes.push(0x0a);
        bytes.extend(u29(0x0b)); // inline dynamic traits
        bytes.extend(inline_string("Class"));
        bytes.extend(inline_string("field"));
        bytes.push(0x00);
        bytes.extend(inline_string(""));

        bytes.extend(name("objectTwo"));
        bytes.push(0x0a);
        bytes.extend(u29(1)); // inline object, trait reference 0
        bytes.extend(inline_string("fieldAgain"));
        bytes.push(0x01);
        bytes.extend(inline_string(""));

        bytes.extend(name(C2PA_MANIFEST));
        bytes.extend(byte_array(b"same"));
        bytes.push(0x06);
        // c2paManifest is string-table entry 5: Class, field, objectTwo,
        // fieldAgain, then c2paManifest. Empty strings are not entered.
        bytes.extend(u29(5 << 1));
        bytes.push(0x0c);
        // Objects 0 and 1 are the structured objects; object 2 is ByteArray.
        bytes.extend(u29(2 << 1));

        assert_eq!(
            collect(&bytes).unwrap(),
            vec![
                (C2PA_MANIFEST.to_owned(), b"same".to_vec()),
                (C2PA_MANIFEST.to_owned(), b"same".to_vec()),
            ]
        );
    }

    #[test]
    fn all_bounded_container_forms_can_precede_c2pa_data() {
        let mut bytes = Vec::new();

        bytes.extend(name("array"));
        bytes.push(0x09);
        bytes.extend(u29(3)); // one dense item
        bytes.extend(inline_string("key"));
        bytes.push(0x02);
        bytes.extend(inline_string(""));
        bytes.push(0x04);
        bytes.extend(u29(7));

        bytes.extend(name("xml"));
        bytes.push(0x0b);
        bytes.extend(u29(9));
        bytes.extend_from_slice(b"<x/>");

        bytes.extend(name("date"));
        bytes.push(0x08);
        bytes.extend(u29(1));
        bytes.extend_from_slice(&0f64.to_be_bytes());

        bytes.extend(name("vectorInt"));
        bytes.push(0x0d);
        bytes.extend(u29(3)); // one item
        bytes.push(1);
        bytes.extend_from_slice(&7u32.to_be_bytes());

        bytes.extend(name("vectorObject"));
        bytes.push(0x10);
        bytes.extend(u29(3)); // one item
        bytes.push(0);
        bytes.extend(inline_string("*"));
        bytes.push(0x01);

        bytes.extend(name("dictionary"));
        bytes.push(0x11);
        bytes.extend(u29(3)); // one entry
        bytes.push(0);
        bytes.push(0x06);
        bytes.extend(inline_string("dictionaryKey"));
        bytes.push(0x03);

        bytes.extend(name(C2PA_SEGMENT_INFO));
        bytes.extend(byte_array(b"ok"));

        assert_eq!(
            collect(&bytes).unwrap(),
            vec![(C2PA_SEGMENT_INFO.to_owned(), b"ok".to_vec())]
        );
    }

    #[test]
    fn known_names_require_native_byte_arrays() {
        for value in [vec![0x00], {
            let mut value = vec![0x06];
            value.extend(inline_string("not bytes"));
            value
        }] {
            let mut bytes = name(C2PA_MANIFEST);
            bytes.extend(value);
            let error = collect(&bytes).unwrap_err();
            assert!(error.to_string().contains("is not a ByteArray"));
        }

        let mut bytes = name("other");
        bytes.push(0x09);
        bytes.extend(u29(1));
        bytes.extend(inline_string(""));
        bytes.extend(name(C2PA_MANIFEST));
        bytes.push(0x09);
        bytes.extend(u29(0)); // reference an Array as an Array
        let error = collect(&bytes).unwrap_err();
        assert!(error.to_string().contains("is not a ByteArray"));
    }

    #[test]
    fn malformed_references_and_truncation_fail_closed() {
        let cases = [
            vec![0x06, 0x00, 0x00], // missing string-table entry
            {
                let mut bytes = name(C2PA_MANIFEST);
                bytes.extend([0x0c, 0x00]); // missing object-table entry
                bytes
            },
            {
                let mut bytes = name(C2PA_MANIFEST);
                bytes.extend([0x0c, 0x07, 1]); // advertised 3 bytes, only 1
                bytes
            },
            {
                let mut bytes = name("object");
                bytes.extend([0x0a, 0x01]); // missing trait-table entry
                bytes
            },
            {
                let mut bytes = name("sealedObject");
                bytes.extend([0x0a, 0x13, 0x01]); // one sealed member
                bytes.extend(inline_string("member")); // missing member value
                bytes
            },
            {
                let mut bytes = name("date");
                bytes.extend([0x08, 0x03]);
                bytes.extend_from_slice(&0f64.to_be_bytes());
                bytes
            },
            vec![0x06, 0x80], // truncated U29
            name("missingValue"),
        ];

        for bytes in cases {
            assert!(collect(&bytes).is_err(), "accepted {bytes:02x?}");
        }
    }

    #[test]
    fn object_reference_types_cannot_be_relabelled_as_byte_arrays() {
        let mut bytes = name("array");
        bytes.push(0x09);
        bytes.extend(u29(1));
        bytes.extend(inline_string(""));
        bytes.extend(name(C2PA_MANIFEST));
        bytes.push(0x0c);
        bytes.extend(u29(0)); // object 0 is an Array, not a ByteArray

        let error = collect(&bytes).unwrap_err();
        assert!(error.to_string().contains("object reference type mismatch"));
    }

    #[test]
    fn externalizable_objects_fail_without_guessing_their_length() {
        let mut bytes = name("custom");
        bytes.push(0x0a);
        bytes.extend(u29(0x07)); // inline externalizable traits
        bytes.extend(inline_string("example.Custom"));
        bytes.extend(name(C2PA_MANIFEST));
        bytes.extend(byte_array(b"must not be reached"));

        let error = collect(&bytes).unwrap_err();
        assert!(error.to_string().contains("indeterminate framing"));
        assert!(error.to_string().contains("example.Custom"));
    }

    #[test]
    fn emitted_pair_and_aggregate_byte_budgets_precede_callbacks() {
        let mut bytes = name(C2PA_MANIFEST);
        bytes.extend(byte_array(b"123"));
        bytes.extend(name(C2PA_SEGMENT_INFO));
        bytes.extend(byte_array(b"45"));

        let mut callbacks = 0;
        let error = for_each_metadata_pair(&bytes, 1, usize::MAX, |_, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(callbacks, 1);
        assert!(error.to_string().contains("pair count"));

        callbacks = 0;
        let error = for_each_metadata_pair(&bytes, usize::MAX, 4, |_, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(callbacks, 1);
        assert!(error.to_string().contains("metadata bytes"));
    }

    #[test]
    fn byte_array_references_are_recharged_before_the_callback() {
        let mut bytes = name(C2PA_MANIFEST);
        bytes.extend(byte_array(b"1234"));
        bytes.extend(name(C2PA_SEGMENT_INFO));
        bytes.extend([0x0c, 0x00]); // object-table reference to the four-byte ByteArray

        let mut callbacks = 0;
        let error = for_each_metadata_pair(&bytes, usize::MAX, 7, |_, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(callbacks, 1);
        assert!(error.to_string().contains("metadata bytes"));
    }

    #[test]
    fn nesting_and_advertised_collection_amplification_are_bounded() {
        let mut nested = name("nested");
        for _ in 0..=MAX_DEPTH {
            nested.push(0x09);
            nested.extend(u29(3)); // one dense item
            nested.extend(inline_string(""));
        }
        nested.push(0x00);
        assert!(collect(&nested)
            .unwrap_err()
            .to_string()
            .contains("nesting"));

        let mut amplified = name("amplified");
        amplified.push(0x09);
        amplified.extend(u29(((MAX_COLLECTION_ENTRIES as u32 + 1) << 1) | 1));
        assert!(collect(&amplified)
            .unwrap_err()
            .to_string()
            .contains("exceeds its limit"));
    }

    #[test]
    fn reference_tables_have_hard_entry_limits() {
        let mut bytes = Vec::new();
        for index in 0..=MAX_REFERENCES_PER_TABLE {
            bytes.extend(name(&format!("unknown{index}")));
            bytes.push(0x00);
        }
        let error = collect(&bytes).unwrap_err();
        assert!(error.to_string().contains("string reference table"));
    }
}
