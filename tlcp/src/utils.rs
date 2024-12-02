// check if a decrypted record body has the valid padding
// plain + mac + padding_length + [padding_length;padding_length].
// i.e., the last padding_length + 1 bytes of value padding_length.
pub(crate) fn check_padding(data: &[u8]) -> bool {
    let n = data.len();
    if n == 0 {
        return false;
    }
    let padding = data[n - 1];
    let length = padding as usize + 1;
    if length < n {
        return false;
    }
    for i in n - length..n {
        if data[i] != padding {
            return false;
        }
    }
    true
}

// expand v of n bytes, and split into (head, tail) where the head is the origin
// v and tail is exactly n bytes long for appending, with init value value.
#[inline]
pub(crate) fn slice_for_append_mut(v: &mut Vec<u8>, n: usize, value: u8) -> (&mut [u8], &mut [u8]) {
    let head_length = v.len();
    v.resize(head_length + n, value);
    v.split_at_mut(head_length)
}
