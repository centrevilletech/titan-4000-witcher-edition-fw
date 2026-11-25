//! The only code that touches modem memory, and so the only `unsafe` code that is
//! not an attribute.
//!
//! - [`Shared`] is a typed handle to a `repr(C)` structure from `modem-atlas` that other
//!   code also reads and writes: stock firmware, N4, the DM console. Access is one
//!   volatile field at a time, and no Rust reference to such memory is ever formed.
//! - A [`Field`] is built by [`field!`] from `offset_of!` and a projection the compiler
//!   type-checks, and its constructor proves it lies inside the structure, aligned. So
//!   a read lands on the declared field at the declared type.
//! - [`m1_decide`] receives hook 4's registers and turns them into safe values: the
//!   bearer as a [`Shared`], and the packet's IP header as the one exclusive slice.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use modem_atlas::Ptr32;
use modem_atlas::addr::{N4_EXT_CNT_VA, N4_STATE_VA};
use modem_atlas::l2::{PdcpUlSduWindow, Rbc};
use modem_atlas::patches::{N4ExtCounters, N4State};

/// Field types that every bit pattern inhabits, so a volatile read is always valid.
pub trait Plain: Copy {}
impl Plain for u16 {}
impl Plain for u32 {}
impl<T> Plain for Ptr32<T> {}

/// The `U` field of `T`, at an offset proven in bounds and aligned.
pub struct Field<T, U> {
    offset: usize,
    _projection: PhantomData<fn(&T) -> &U>,
}

impl<T, U> Clone for Field<T, U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, U> Copy for Field<T, U> {}

impl<T, U> Field<T, U> {
    /// Use [`field!`]. `_projection` is never called: it makes the compiler check that
    /// `U` is the field's type. The assertion runs at compile time in a `const`.
    pub const fn new(offset: usize, _projection: fn(&T) -> &U) -> Self {
        assert!(offset.is_multiple_of(align_of::<U>()) && offset + size_of::<U>() <= size_of::<T>());
        Self {
            offset,
            _projection: PhantomData,
        }
    }
}

/// `field!(Type, name)`: a [`Field`] for `Type::name`, built at compile time.
macro_rules! field {
    ($ty:ty, $name:ident) => {
        const { $crate::modem::hw::Field::<$ty, _>::new(core::mem::offset_of!($ty, $name), |s: &$ty| &s.$name) }
    };
}
pub(crate) use field;

/// A live `T` in modem memory, shared with code outside Rust.
pub struct Shared<T>(NonNull<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Shared<T> {}

impl<T> Shared<T> {
    /// # Safety
    ///
    /// `ptr` must address a live, aligned `T` that stays valid for volatile reads and
    /// writes for the rest of the program, and no Rust reference to it may exist.
    const unsafe fn new(ptr: NonNull<T>) -> Self {
        Self(ptr)
    }

    /// The `U` at `offset` bytes into the `T`. Private: every offset comes from a
    /// [`Field`] (in bounds and aligned by construction) or a bounds-checked index.
    fn read<U: Plain>(self, offset: usize) -> U {
        let ptr = self.0.as_ptr().wrapping_byte_add(offset).cast::<U>();
        // SAFETY: `new` makes the whole `T` valid for volatile reads, the offset puts the
        // `U` inside it, aligned, and every bit pattern is a valid `U`.
        unsafe { ptr.read_volatile() }
    }

    fn write<U: Plain>(self, offset: usize, value: U) {
        let ptr = self.0.as_ptr().wrapping_byte_add(offset).cast::<U>();
        // SAFETY: as in `read`, for volatile writes.
        unsafe { ptr.write_volatile(value) }
    }

    pub fn get<U: Plain>(self, field: Field<T, U>) -> U {
        self.read(field.offset)
    }

    pub fn set<U: Plain>(self, field: Field<T, U>, value: U) {
        self.write(field.offset, value);
    }

    pub fn bump(self, field: Field<T, u32>) {
        self.set(field, self.get(field).wrapping_add(1));
    }

    /// `field` of element `index` of `array`, or `None` past the array's end.
    pub fn get_element<E, U: Plain, const N: usize>(
        self,
        array: Field<T, [E; N]>,
        index: usize,
        field: Field<E, U>,
    ) -> Option<U> {
        (index < N).then(|| self.read(array.offset + index * size_of::<E>() + field.offset))
    }
}

/// N4's engine state (`0x847e_d600`), shared with N4's hooks (asm N4 or R4's Rust N4).
pub const N4: Shared<N4State> = fixed(N4_STATE_VA);
/// N4's always-on counters (`0x847e_d780`).
pub const N4_EXT: Shared<N4ExtCounters> = fixed(N4_EXT_CNT_VA);

const fn fixed<T>(va: u32) -> Shared<T> {
    let Some(ptr) = NonNull::new(va as usize as *mut T) else {
        panic!("null modem address");
    };
    // SAFETY: only for the two atlas addresses above. N4's image places those blocks
    // there for the life of the firmware, aligned, in RAM CPU1 maps read-write.
    unsafe { Shared::new(ptr) }
}

/// The bearer's PDCP uplink SDU window, if it has one.
pub fn pdcp_window(rbc: Shared<Rbc>) -> Option<Shared<PdcpUlSduWindow>> {
    let window = NonNull::new(rbc.get(field!(Rbc, pdcp_ul_win)).as_mut_ptr())?;
    // SAFETY: stock PDCP keeps `pdcp_ul_win` null or pointing at this bearer's live
    // window (`proc_pdcp_ul`, `0x842d_cac0`; lane M2's atlas).
    Some(unsafe { Shared::new(window) })
}

/// Bytes of the packet the AQM sees: an IPv6 header and its TCP or UDP ports (the
/// flow hash), and every IPv4 header field it reads.
const IP_VIEW: u32 = 44;

/// Hook 4's view of a bulk packet, built from the shim's registers.
pub struct Packet<'a> {
    pub rbc: Shared<Rbc>,
    /// The first `min(len, IP_VIEW)` bytes of the IP packet.
    pub ip: &'a mut [u8],
    pub len: u32,
    pub now: u32,
}

/// The Rust side of `m1_aqm_shim`: `r9` (bearer), `r4` (IP length), `r6` (TTI clock),
/// `sl` (IRB buffer). Returns 0 for Exit B (enqueue) and 1 for Exit D (drop).
pub extern "C" fn m1_decide(rbc: *mut Rbc, len: u32, now: u32, buf: *mut u8) -> u32 {
    let (Some(rbc), Some(buf)) = (NonNull::new(rbc), NonNull::new(buf)) else {
        return 0;
    };
    // SAFETY: at hook 4, `r9` is the bearer `l2_task` is enqueuing to, a live `Rbc` in its
    // bearer table for the life of the firmware.
    let rbc = unsafe { Shared::new(rbc) };
    let ip = buf.as_ptr().wrapping_add(2);
    // SAFETY: `sl` is the IRB buffer `l2_task` owns until it enqueues or frees this
    // packet: a 2-byte GIPC prefix, then `len` bytes of IP packet. Nothing else touches
    // it before the hook returns, and the slice does not outlive this call.
    let ip = unsafe { core::slice::from_raw_parts_mut(ip, len.min(IP_VIEW) as usize) };
    super::on_packet(Packet { rbc, ip, len, now }) as u32
}
