// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use super::Value;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RangeError {
    Malformed,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BoxExclusion {
    pub box_index: usize,
    pub start: usize,
    pub length: usize,
}

fn nonnegative_usize(value: Option<&Value>) -> Option<usize> {
    match value {
        Some(Value::Integer(value)) if *value >= 0 => usize::try_from(*value).ok(),
        _ => None,
    }
}

fn items(value: Option<&Value>) -> Result<&[Value], RangeError> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(RangeError::Malformed),
    }
}

pub(super) fn parse_data(
    value: Option<&Value>,
    asset_len: usize,
) -> Result<Vec<(usize, usize)>, RangeError> {
    let items = items(value)?;
    if items.len() > super::MAX_DATA_HASH_EXCLUSIONS {
        return Err(RangeError::Malformed);
    }
    let mut ranges = Vec::with_capacity(items.len());
    let mut previous_end = 0usize;
    for (index, item) in items.iter().enumerate() {
        let start = nonnegative_usize(item.get("start")).ok_or(RangeError::Malformed)?;
        let length = nonnegative_usize(item.get("length")).ok_or(RangeError::Malformed)?;
        let end = start.checked_add(length).ok_or(RangeError::Malformed)?;
        if index > 0 && start < previous_end {
            return Err(RangeError::Malformed);
        }
        if end > asset_len {
            return Err(RangeError::Mismatch);
        }
        previous_end = end;
        ranges.push((start, length));
    }
    Ok(ranges)
}

pub(super) fn parse_boxes(
    value: Option<&Value>,
    box_lengths: &[usize],
) -> Result<Vec<BoxExclusion>, RangeError> {
    let items = items(value)?;
    if items.len() > super::MAX_DATA_HASH_EXCLUSIONS {
        return Err(RangeError::Malformed);
    }
    let mut ranges = Vec::with_capacity(items.len());
    let mut previous: Option<(usize, usize)> = None;
    for item in items {
        let box_index = match item.get("boxIndex") {
            Some(value) => nonnegative_usize(Some(value)).ok_or(RangeError::Malformed)?,
            None if box_lengths.len() == 1 => 0,
            None => return Err(RangeError::Malformed),
        };
        let box_len = box_lengths
            .get(box_index)
            .copied()
            .ok_or(RangeError::Malformed)?;
        let start = nonnegative_usize(item.get("start")).ok_or(RangeError::Malformed)?;
        let length = nonnegative_usize(item.get("length")).ok_or(RangeError::Malformed)?;
        let end = start.checked_add(length).ok_or(RangeError::Malformed)?;
        if let Some((previous_box, previous_end)) = previous {
            if box_index < previous_box || (box_index == previous_box && start < previous_end) {
                return Err(RangeError::Malformed);
            }
        }
        if end > box_len {
            return Err(RangeError::Mismatch);
        }
        previous = Some((box_index, end));
        ranges.push(BoxExclusion {
            box_index,
            start,
            length,
        });
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: i128, length: i128) -> Value {
        Value::Map(vec![
            (Value::Text("start".into()), Value::Integer(start)),
            (Value::Text("length".into()), Value::Integer(length)),
        ])
    }

    fn box_range(box_index: Option<i128>, start: i128, length: i128) -> Value {
        let mut fields = vec![
            (Value::Text("start".into()), Value::Integer(start)),
            (Value::Text("length".into()), Value::Integer(length)),
        ];
        if let Some(index) = box_index {
            fields.push((Value::Text("boxIndex".into()), Value::Integer(index)));
        }
        Value::Map(fields)
    }

    #[test]
    fn data_exclusions_reject_negative_unsorted_and_overlapping_ranges() {
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(-1, 2)])), 100),
            Err(RangeError::Malformed)
        );
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(10, 2), range(2, 2)])), 100),
            Err(RangeError::Malformed)
        );
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(2, 10), range(8, 2)])), 100),
            Err(RangeError::Malformed)
        );
    }

    #[test]
    fn data_exclusions_reject_overflow_and_out_of_asset_ranges() {
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(i128::MAX, 2)])), 100),
            Err(RangeError::Malformed)
        );
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(90, 11)])), 100),
            Err(RangeError::Mismatch)
        );
    }

    #[test]
    fn data_exclusions_preserve_signed_order() {
        assert_eq!(
            parse_data(Some(&Value::Array(vec![range(2, 3), range(5, 4)])), 20).unwrap(),
            vec![(2, 3), (5, 4)]
        );
    }

    #[test]
    fn box_exclusions_validate_box_index_and_local_bounds() {
        assert_eq!(
            parse_boxes(
                Some(&Value::Array(vec![box_range(Some(2), 0, 1)])),
                &[10, 10]
            ),
            Err(RangeError::Malformed)
        );
        assert_eq!(
            parse_boxes(Some(&Value::Array(vec![box_range(None, 8, 3)])), &[10]),
            Err(RangeError::Mismatch)
        );
        assert_eq!(
            parse_boxes(
                Some(&Value::Array(vec![
                    box_range(Some(1), 4, 2),
                    box_range(Some(1), 3, 1),
                ])),
                &[10, 10],
            ),
            Err(RangeError::Malformed)
        );
    }
}
