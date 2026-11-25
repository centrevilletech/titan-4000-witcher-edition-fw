//! zlib 1.3's trees.c for one configuration (memLevel 8, default strategy):
//! the symbol buffer, the Huffman trees, and block output. Part of the
//! zlib port in `deflate.rs`; its license notice there covers this file.
//!
//! Altered from the original: translated to Rust, debug code and the
//! strategies and flush modes Witcher does not use removed. A node keeps
//! zlib's two unions (freq or code, dad or len) as `fc` and `dl`.

use alloc::vec;
use alloc::vec::Vec;

const LENGTH_CODES: usize = 29;
const LITERALS: usize = 256;
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
const D_CODES: usize = 30;
const BL_CODES: usize = 19;
const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;
const MAX_BL_BITS: usize = 7;
const END_BLOCK: usize = 256;
const REP_3_6: usize = 16;
const REPZ_3_10: usize = 17;
const REPZ_11_138: usize = 18;
const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;
/// zlib's lit_bufsize for memLevel 8: a block holds at most this many symbols, less one.
pub(crate) const LIT_BUFSIZE: usize = 1 << (8 + 6);

const EXTRA_LBITS: [u8; LENGTH_CODES] =
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const EXTRA_DBITS: [u8; D_CODES] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const EXTRA_BLBITS: [u8; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
const BL_ORDER: [u8; BL_CODES] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

#[derive(Clone, Copy, Default)]
struct Node {
    /// Frequency while the tree is built, then the code.
    fc: u16,
    /// Parent while the tree is built, then the code length.
    dl: u16,
}

/// zlib's static_tree_desc.
struct Desc {
    extra: &'static [u8],
    base: usize,
    elems: usize,
    max_length: usize,
}

const L_DESC: Desc = Desc { extra: &EXTRA_LBITS, base: LITERALS + 1, elems: L_CODES, max_length: MAX_BITS };
const D_DESC: Desc = Desc { extra: &EXTRA_DBITS, base: 0, elems: D_CODES, max_length: MAX_BITS };
const BL_DESC: Desc = Desc { extra: &EXTRA_BLBITS, base: 0, elems: BL_CODES, max_length: MAX_BL_BITS };

/// tr_static_init's tables.
struct Tables {
    base_length: [u8; LENGTH_CODES],
    length_code: [u8; 256],
    base_dist: [u16; D_CODES],
    dist_code: [u8; 512],
    static_ltree: [Node; L_CODES + 2],
    static_dtree: [Node; D_CODES],
}

static TABLES: Tables = tables();

const fn tables() -> Tables {
    let mut t = Tables {
        base_length: [0; LENGTH_CODES],
        length_code: [0; 256],
        base_dist: [0; D_CODES],
        dist_code: [0; 512],
        static_ltree: [Node { fc: 0, dl: 0 }; L_CODES + 2],
        static_dtree: [Node { fc: 0, dl: 0 }; D_CODES],
    };
    let mut length = 0;
    let mut code = 0;
    while code < LENGTH_CODES - 1 {
        t.base_length[code] = length as u8;
        let mut n = 0;
        while n < 1 << EXTRA_LBITS[code] {
            t.length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    // Length 258 has two encodings; zlib picks code 285.
    t.length_code[255] = (LENGTH_CODES - 1) as u8;
    let mut dist = 0;
    code = 0;
    while code < 16 {
        t.base_dist[code] = dist as u16;
        let mut n = 0;
        while n < 1 << EXTRA_DBITS[code] {
            t.dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    dist >>= 7;
    while code < D_CODES {
        t.base_dist[code] = (dist << 7) as u16;
        let mut n = 0;
        while n < 1 << (EXTRA_DBITS[code] - 7) {
            t.dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    let mut bl_count = [0u16; MAX_BITS + 1];
    let mut n = 0;
    while n < L_CODES + 2 {
        let len = if n <= 143 {
            8
        } else if n <= 255 {
            9
        } else if n <= 279 {
            7
        } else {
            8
        };
        t.static_ltree[n].dl = len;
        bl_count[len as usize] += 1;
        n += 1;
    }
    gen_codes(&mut t.static_ltree, L_CODES + 1, &bl_count);
    n = 0;
    while n < D_CODES {
        t.static_dtree[n] = Node { fc: bi_reverse(n as u32, 5) as u16, dl: 5 };
        n += 1;
    }
    t
}

const fn bi_reverse(mut code: u32, mut len: u32) -> u32 {
    let mut res = 0;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            return res >> 1;
        }
    }
}

const fn gen_codes(tree: &mut [Node], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code: u32 = 0;
    let mut bits = 1;
    while bits <= MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code as u16;
        bits += 1;
    }
    let mut n = 0;
    while n <= max_code {
        let len = tree[n].dl as usize;
        if len != 0 {
            tree[n].fc = bi_reverse(next_code[len] as u32, len as u32) as u16;
            next_code[len] = next_code[len].wrapping_add(1);
        }
        n += 1;
    }
}

fn d_code(dist: usize) -> usize {
    (if dist < 256 { TABLES.dist_code[dist] } else { TABLES.dist_code[256 + (dist >> 7)] }) as usize
}

/// Bits out, least significant first, as zlib's send_bits writes them.
struct BitWriter {
    out: Vec<u8>,
    bits: u64,
    count: u32,
}

impl BitWriter {
    fn send(&mut self, value: u32, len: u32) {
        self.bits |= (value as u64 & ((1u64 << len) - 1)) << self.count;
        self.count += len;
        while self.count >= 8 {
            self.out.push(self.bits as u8);
            self.bits >>= 8;
            self.count -= 8;
        }
    }

    fn code(&mut self, c: usize, tree: &[Node]) {
        self.send(tree[c].fc as u32, tree[c].dl as u32);
    }

    /// bi_windup: pad to a byte boundary.
    fn windup(&mut self) {
        if self.count > 0 {
            self.out.push(self.bits as u8);
        }
        self.bits = 0;
        self.count = 0;
    }
}

/// The heap build_tree works in, and the bit length counts.
struct Heap {
    heap: [u16; HEAP_SIZE],
    len: usize,
    max: usize,
    depth: [u8; HEAP_SIZE],
    bl_count: [u16; MAX_BITS + 1],
}

/// The current block's size in bits with dynamic and with static trees.
/// zlib lets these pass below zero mid-build (unsigned), so they wrap.
#[derive(Default)]
struct Lens {
    opt: u64,
    stat: u64,
}

pub(crate) struct Trees {
    dyn_ltree: [Node; HEAP_SIZE],
    dyn_dtree: [Node; 2 * D_CODES + 1],
    bl_tree: [Node; 2 * BL_CODES + 1],
    l_max_code: usize,
    d_max_code: usize,
    heap: Heap,
    lens: Lens,
    sym_dist: Vec<u16>,
    sym_lc: Vec<u8>,
    sym_next: usize,
    bits: BitWriter,
}

impl Trees {
    pub(crate) fn new() -> Self {
        let mut t = Trees {
            dyn_ltree: [Node::default(); HEAP_SIZE],
            dyn_dtree: [Node::default(); 2 * D_CODES + 1],
            bl_tree: [Node::default(); 2 * BL_CODES + 1],
            l_max_code: 0,
            d_max_code: 0,
            heap: Heap {
                heap: [0; HEAP_SIZE],
                len: 0,
                max: 0,
                depth: [0; HEAP_SIZE],
                bl_count: [0; MAX_BITS + 1],
            },
            lens: Lens::default(),
            sym_dist: vec![0; LIT_BUFSIZE],
            sym_lc: vec![0; LIT_BUFSIZE],
            sym_next: 0,
            bits: BitWriter { out: Vec::new(), bits: 0, count: 0 },
        };
        t.init_block();
        t
    }

    /// The compressed bytes written so far; the caller drains them.
    pub(crate) fn output(&mut self) -> &mut Vec<u8> {
        &mut self.bits.out
    }

    /// _tr_tally_lit. True when the block is full.
    pub(crate) fn tally_lit(&mut self, c: u8) -> bool {
        self.sym_dist[self.sym_next] = 0;
        self.sym_lc[self.sym_next] = c;
        self.sym_next += 1;
        self.dyn_ltree[c as usize].fc += 1;
        self.sym_next == LIT_BUFSIZE - 1
    }

    /// _tr_tally_dist: a match `dist` back, of length `lc` + 3. True when the block is full.
    pub(crate) fn tally_dist(&mut self, dist: usize, lc: usize) -> bool {
        self.sym_dist[self.sym_next] = dist as u16;
        self.sym_lc[self.sym_next] = lc as u8;
        self.sym_next += 1;
        self.dyn_ltree[TABLES.length_code[lc] as usize + LITERALS + 1].fc += 1;
        self.dyn_dtree[d_code(dist - 1)].fc += 1;
        self.sym_next == LIT_BUFSIZE - 1
    }

    fn init_block(&mut self) {
        for node in &mut self.dyn_ltree[..L_CODES] {
            node.fc = 0;
        }
        for node in &mut self.dyn_dtree[..D_CODES] {
            node.fc = 0;
        }
        for node in &mut self.bl_tree[..BL_CODES] {
            node.fc = 0;
        }
        self.dyn_ltree[END_BLOCK].fc = 1;
        self.lens = Lens::default();
        self.sym_next = 0;
    }

    /// _tr_flush_block. `stored` is the block's input when it is still in
    /// the window (zlib's buf != NULL), so a stored block is possible.
    pub(crate) fn flush_block(&mut self, stored: Option<&[u8]>, last: bool) {
        let ls: &[Node] = &TABLES.static_ltree;
        let ds: &[Node] = &TABLES.static_dtree;
        self.l_max_code = build_tree(&mut self.dyn_ltree, Some(ls), &L_DESC, &mut self.heap, &mut self.lens);
        self.d_max_code = build_tree(&mut self.dyn_dtree, Some(ds), &D_DESC, &mut self.heap, &mut self.lens);
        let max_blindex = self.build_bl_tree();
        let mut opt_lenb = self.lens.opt.wrapping_add(3 + 7) >> 3;
        let static_lenb = self.lens.stat.wrapping_add(3 + 7) >> 3;
        if static_lenb <= opt_lenb {
            opt_lenb = static_lenb;
        }
        let last_bit = last as u32;
        let (dist, lc) = (&self.sym_dist[..self.sym_next], &self.sym_lc[..self.sym_next]);
        match stored {
            Some(buf) if buf.len() as u64 + 4 <= opt_lenb => {
                debug_assert!(buf.len() <= 0xffff, "zlib keeps stored blocks within the window");
                self.bits.send((STORED_BLOCK << 1) + last_bit, 3);
                self.bits.windup();
                let len = buf.len() as u16;
                self.bits.out.extend_from_slice(&len.to_le_bytes());
                self.bits.out.extend_from_slice(&(!len).to_le_bytes());
                self.bits.out.extend_from_slice(buf);
            }
            _ if static_lenb == opt_lenb => {
                self.bits.send((STATIC_TREES << 1) + last_bit, 3);
                compress_block(&mut self.bits, dist, lc, ls, ds);
            }
            _ => {
                self.bits.send((DYN_TREES << 1) + last_bit, 3);
                let (lcodes, dcodes) = (self.l_max_code + 1, self.d_max_code + 1);
                send_all_trees(&mut self.bits, &self.dyn_ltree, lcodes, &self.dyn_dtree, dcodes, &self.bl_tree, max_blindex + 1);
                compress_block(&mut self.bits, dist, lc, &self.dyn_ltree, &self.dyn_dtree);
            }
        }
        self.init_block();
        if last {
            self.bits.windup();
        }
    }

    fn build_bl_tree(&mut self) -> usize {
        scan_tree(&mut self.dyn_ltree, self.l_max_code, &mut self.bl_tree);
        scan_tree(&mut self.dyn_dtree, self.d_max_code, &mut self.bl_tree);
        build_tree(&mut self.bl_tree, None, &BL_DESC, &mut self.heap, &mut self.lens);
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 && self.bl_tree[BL_ORDER[max_blindex] as usize].dl == 0 {
            max_blindex -= 1;
        }
        self.lens.opt = self.lens.opt.wrapping_add(3 * (max_blindex as u64 + 1) + 5 + 5 + 4);
        max_blindex
    }

}

/// zlib's send_all_trees: the dynamic block header.
fn send_all_trees(
    bits: &mut BitWriter,
    ltree: &[Node],
    lcodes: usize,
    dtree: &[Node],
    dcodes: usize,
    bl: &[Node],
    blcodes: usize,
) {
    bits.send((lcodes - 257) as u32, 5);
    bits.send((dcodes - 1) as u32, 5);
    bits.send((blcodes - 4) as u32, 4);
    for &rank in &BL_ORDER[..blcodes] {
        bits.send(bl[rank as usize].dl as u32, 3);
    }
    send_tree(bits, ltree, lcodes - 1, bl);
    send_tree(bits, dtree, dcodes - 1, bl);
}

/// zlib's compress_block: the block's symbols with the chosen trees.
fn compress_block(bits: &mut BitWriter, dists: &[u16], lcs: &[u8], ltree: &[Node], dtree: &[Node]) {
    for (&dist, &lc) in dists.iter().zip(lcs) {
        if dist == 0 {
            bits.code(lc as usize, ltree);
            continue;
        }
        let code = TABLES.length_code[lc as usize] as usize;
        bits.code(code + LITERALS + 1, ltree);
        let extra = EXTRA_LBITS[code] as u32;
        if extra != 0 {
            bits.send(lc as u32 - TABLES.base_length[code] as u32, extra);
        }
        let dist = dist as usize - 1;
        let code = d_code(dist);
        bits.code(code, dtree);
        let extra = EXTRA_DBITS[code] as u32;
        if extra != 0 {
            bits.send((dist - TABLES.base_dist[code] as usize) as u32, extra);
        }
    }
    bits.code(END_BLOCK, ltree);
}

fn smaller(tree: &[Node], depth: &[u8], n: usize, m: usize) -> bool {
    tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && depth[n] <= depth[m])
}

fn pqdownheap(tree: &[Node], h: &mut Heap, mut k: usize) {
    let v = h.heap[k] as usize;
    let mut j = k << 1;
    while j <= h.len {
        if j < h.len && smaller(tree, &h.depth, h.heap[j + 1] as usize, h.heap[j] as usize) {
            j += 1;
        }
        if smaller(tree, &h.depth, v, h.heap[j] as usize) {
            break;
        }
        h.heap[k] = h.heap[j];
        k = j;
        j <<= 1;
    }
    h.heap[k] = v as u16;
}

/// zlib's build_tree: Huffman code lengths and codes for one tree. Returns max_code.
fn build_tree(tree: &mut [Node], stree: Option<&[Node]>, d: &Desc, h: &mut Heap, lens: &mut Lens) -> usize {
    let mut max_code: isize = -1;
    h.len = 0;
    h.max = HEAP_SIZE;
    for n in 0..d.elems {
        if tree[n].fc != 0 {
            h.len += 1;
            h.heap[h.len] = n as u16;
            max_code = n as isize;
            h.depth[n] = 0;
        } else {
            tree[n].dl = 0;
        }
    }
    // The format needs at least one distance code and one bit per code, so
    // zlib forces two codes of nonzero frequency.
    while h.len < 2 {
        let node = if max_code < 2 {
            max_code += 1;
            max_code as usize
        } else {
            0
        };
        h.len += 1;
        h.heap[h.len] = node as u16;
        tree[node].fc = 1;
        h.depth[node] = 0;
        lens.opt = lens.opt.wrapping_sub(1);
        if let Some(st) = stree {
            lens.stat = lens.stat.wrapping_sub(st[node].dl as u64);
        }
    }
    let max_code = max_code as usize;
    for n in (1..=h.len / 2).rev() {
        pqdownheap(tree, h, n);
    }
    let mut node = d.elems;
    loop {
        let n = h.heap[1] as usize;
        h.heap[1] = h.heap[h.len];
        h.len -= 1;
        pqdownheap(tree, h, 1);
        let m = h.heap[1] as usize;
        h.max -= 1;
        h.heap[h.max] = n as u16;
        h.max -= 1;
        h.heap[h.max] = m as u16;
        tree[node].fc = tree[n].fc.wrapping_add(tree[m].fc);
        h.depth[node] = h.depth[n].max(h.depth[m]).wrapping_add(1);
        tree[n].dl = node as u16;
        tree[m].dl = node as u16;
        h.heap[1] = node as u16;
        node += 1;
        pqdownheap(tree, h, 1);
        if h.len < 2 {
            break;
        }
    }
    h.max -= 1;
    h.heap[h.max] = h.heap[1];
    gen_bitlen(tree, max_code, stree, d, h, lens);
    gen_codes(tree, max_code, &h.bl_count);
    max_code
}

/// zlib's gen_bitlen: code lengths from the tree, capped at max_length with
/// zlib's overflow repair, and the block's size in bits.
fn gen_bitlen(tree: &mut [Node], max_code: usize, stree: Option<&[Node]>, d: &Desc, h: &mut Heap, lens: &mut Lens) {
    h.bl_count = [0; MAX_BITS + 1];
    let mut overflow: i32 = 0;
    tree[h.heap[h.max] as usize].dl = 0;
    for i in h.max + 1..HEAP_SIZE {
        let n = h.heap[i] as usize;
        let mut bits = tree[tree[n].dl as usize].dl as usize + 1;
        if bits > d.max_length {
            bits = d.max_length;
            overflow += 1;
        }
        tree[n].dl = bits as u16;
        if n > max_code {
            continue;
        }
        h.bl_count[bits] += 1;
        let xbits = if n >= d.base { d.extra[n - d.base] as u64 } else { 0 };
        let f = tree[n].fc as u64;
        lens.opt = lens.opt.wrapping_add(f * (bits as u64 + xbits));
        if let Some(st) = stree {
            lens.stat = lens.stat.wrapping_add(f * (st[n].dl as u64 + xbits));
        }
    }
    if overflow == 0 {
        return;
    }
    loop {
        let mut bits = d.max_length - 1;
        while h.bl_count[bits] == 0 {
            bits -= 1;
        }
        h.bl_count[bits] -= 1;
        h.bl_count[bits + 1] += 2;
        h.bl_count[d.max_length] -= 1;
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }
    let mut i = HEAP_SIZE;
    for bits in (1..=d.max_length).rev() {
        let mut n = h.bl_count[bits];
        while n != 0 {
            i -= 1;
            let m = h.heap[i] as usize;
            if m > max_code {
                continue;
            }
            if tree[m].dl as usize != bits {
                let delta = (bits as u64).wrapping_sub(tree[m].dl as u64);
                lens.opt = lens.opt.wrapping_add(delta.wrapping_mul(tree[m].fc as u64));
                tree[m].dl = bits as u16;
            }
            n -= 1;
        }
    }
}

/// The repeat-count state scan_tree and send_tree share.
fn run_limits(curlen: u32, nextlen: u32) -> (u32, u32) {
    if nextlen == 0 {
        (138, 3)
    } else if curlen == nextlen {
        (6, 3)
    } else {
        (7, 4)
    }
}

/// zlib's scan_tree: count the bit length codes a tree's lengths need. Sets
/// zlib's guard length (0xffff) after max_code, which send_tree relies on.
fn scan_tree(tree: &mut [Node], max_code: usize, bl: &mut [Node]) {
    let mut prevlen = u32::MAX;
    let mut nextlen = tree[0].dl as u32;
    let mut count = 0;
    let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };
    tree[max_code + 1].dl = 0xffff;
    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = tree[n + 1].dl as u32;
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            bl[curlen as usize].fc += count as u16;
        } else if curlen != 0 {
            if curlen != prevlen {
                bl[curlen as usize].fc += 1;
            }
            bl[REP_3_6].fc += 1;
        } else if count <= 10 {
            bl[REPZ_3_10].fc += 1;
        } else {
            bl[REPZ_11_138].fc += 1;
        }
        count = 0;
        prevlen = curlen;
        (max_count, min_count) = run_limits(curlen, nextlen);
    }
}

/// zlib's send_tree: a tree's code lengths in bit length codes.
fn send_tree(bits: &mut BitWriter, tree: &[Node], max_code: usize, bl: &[Node]) {
    let mut prevlen = u32::MAX;
    let mut nextlen = tree[0].dl as u32;
    let mut count = 0;
    let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };
    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = tree[n + 1].dl as u32;
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            for _ in 0..count {
                bits.code(curlen as usize, bl);
            }
        } else if curlen != 0 {
            if curlen != prevlen {
                bits.code(curlen as usize, bl);
                count -= 1;
            }
            bits.code(REP_3_6, bl);
            bits.send(count - 3, 2);
        } else if count <= 10 {
            bits.code(REPZ_3_10, bl);
            bits.send(count - 3, 3);
        } else {
            bits.code(REPZ_11_138, bl);
            bits.send(count - 11, 7);
        }
        count = 0;
        prevlen = curlen;
        (max_count, min_count) = run_limits(curlen, nextlen);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_tables_match_zlib() {
        // trees.h in zlib 1.3: static_ltree[0], [143], [144], [255], [256], [279], [280], [287].
        let lt = &TABLES.static_ltree;
        let pairs = [(0, 12, 8), (143, 253, 8), (144, 19, 9), (255, 511, 9), (256, 0, 7), (279, 116, 7), (280, 3, 8), (287, 227, 8)];
        for (n, code, len) in pairs {
            assert_eq!((lt[n].fc, lt[n].dl), (code, len), "static_ltree[{n}]");
        }
        assert_eq!((TABLES.static_dtree[1].fc, TABLES.static_dtree[1].dl), (16, 5));
        assert_eq!(TABLES.length_code[0], 0);
        assert_eq!(TABLES.length_code[8], 8);
        assert_eq!(TABLES.length_code[254], 27);
        assert_eq!(TABLES.length_code[255], 28);
        assert_eq!(TABLES.base_length[28], 0);
        assert_eq!(d_code(0), 0);
        assert_eq!(d_code(4), 4);
        assert_eq!(d_code(255), 15);
        assert_eq!(d_code(256), 16);
        assert_eq!(d_code(32767), 29);
        assert_eq!(TABLES.base_dist[29], 24576);
    }
}
