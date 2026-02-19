#[allow(dead_code)]
pub fn decode_var_u32(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];

    // 0xxxxxxx -> 1 byte
    if first < 0x80 {
        return Some((first as u32, 1));
    }

    // 10xxxxxx -> 2 bytes
    if first < 0xC0 {
        if data.len() < 2 {
            return None;
        }
        // 0x80 = 1000 0000. mask 0x3F.
        // value = (first & 0x3F) << 8 | next
        let high = (first & 0x3F) as u32;
        let low = data[1] as u32;
        return Some(((high << 8) | low, 2));
    }

    // 110xxxxx -> 3 bytes
    if first < 0xE0 {
        if data.len() < 3 {
            return None;
        }
        let high = (first & 0x1F) as u32;
        // Rest is LE u16
        let low = u16::from_le_bytes([data[1], data[2]]) as u32;
        return Some(((high << 16) | low, 3));
    }

    // 1110xxxx -> 4 bytes
    if first < 0xF0 {
        if data.len() < 4 {
            return None;
        }
        let high = (first & 0x0F) as u32;
        // Rest is LE u24 (3 bytes)
        let low = (data[1] as u32) | ((data[2] as u32) << 8) | ((data[3] as u32) << 16);
        return Some(((high << 24) | low, 4));
    }

    // 11110xxx -> 5 bytes
    if first < 0xF8 {
        if data.len() < 5 {
            return None;
        }
        // first must be F0 for u32 range.
        if first != 0xF0 {
            return None;
        }
        let low = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        return Some((low, 5));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_known_values() {
        assert_eq!(decode_var_u32(&[0]), Some((0, 1)));
        assert_eq!(decode_var_u32(&[1]), Some((1, 1)));
        assert_eq!(decode_var_u32(&[127]), Some((127, 1)));

        assert_eq!(decode_var_u32(&[0x80, 0x80]), Some((128, 2)));
        assert_eq!(decode_var_u32(&[0x80, 0x91]), Some((145, 2)));
        assert_eq!(decode_var_u32(&[0x81, 0x2c]), Some((300, 2)));

        assert_eq!(decode_var_u32(&[0xbf, 0xff]), Some((16383, 2)));

        assert_eq!(decode_var_u32(&[0xc0, 0x00, 0x40]), Some((16384, 3)));

        // u32::MAX -> F0 FF FF FF FF
        assert_eq!(
            decode_var_u32(&[0xF0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Some((u32::MAX, 5))
        );
    }
}
