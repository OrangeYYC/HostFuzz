pub fn set_octet_bit(bytes: &mut [u8], octet: usize, bit: usize, val: bool) {
    if val {
        bytes[octet] |= 1 << bit;
    } else {
        bytes[octet] &= !(1 << bit);
    }
}

pub fn set_bit(bytes: &mut [u8], id: usize, val: bool) {
    if id < bytes.len() * 8 {
        let octet = id / 8;
        let bit = id % 8;
        set_octet_bit(bytes, octet, bit, val);
    }
}

pub fn get_octet_bit(bytes: &[u8], octet: usize, bit: usize) -> bool {
    bytes[octet] & (1 << bit) != 0
}

pub fn get_bit(bytes: &[u8], id: usize) -> bool {
    if id < bytes.len() * 8 {
        let octet = id / 8;
        let bit = id % 8;
        get_octet_bit(bytes, octet, bit)
    } else {
        false
    }
}
