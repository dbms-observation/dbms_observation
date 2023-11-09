use crate::util;
use crate::Addr;
use crate::Pid;
use crate::Result;

use super::user::normalize_user_addrs_sorted_impl;
use super::user::NormalizedUserAddrs;


/// A type capturing normalized addresses along with captured meta data.
///
/// This type enables "remote" symbolization. That is to say, it represents the
/// input necessary for addresses to be symbolized on a system other than where
/// they were recorded.
#[derive(Clone, Debug)]
pub struct NormalizedAddrs<M> {
    /// Normalized addresses along with an index into `meta` for retrieval of
    /// the corresponding [`AddrMeta`] information.
    ///
    /// A normalized address is one as it would appear in a binary or debug
    /// symbol file, i.e., one excluding any relocations.
    pub addrs: Vec<(Addr, usize)>,
    /// Meta information about the normalized addresses.
    pub meta: Vec<M>,
}


/// A builder for configurable construction of [`Normalizer`] objects.
///
/// By default all features are enabled.
#[derive(Clone, Debug)]
pub struct Builder {
    /// Whether to read and report build IDs as part of the
    /// normalization process.
    build_ids: bool,
}

impl Builder {
    /// Enable/disable the reading of build IDs.
    pub fn enable_build_ids(mut self, enable: bool) -> Builder {
        self.build_ids = enable;
        self
    }

    /// Create the [`Normalizer`] object.
    pub fn build(self) -> Normalizer {
        let Builder { build_ids } = self;

        Normalizer { build_ids }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self { build_ids: true }
    }
}


/// A normalizer for addresses.
///
/// Address normalization is the process of taking virtual absolute
/// addresses as they are seen by, say, a process (which include
/// relocation and process specific layout randomizations, among other
/// things) and converting them to "normalized" virtual addresses as
/// they are present in, say, an ELF binary or a DWARF debug info file,
/// and one would be able to see them using tools such as readelf(1).
#[derive(Debug, Default)]
pub struct Normalizer {
    /// Flag indicating whether or not to read build IDs as part of the
    /// normalization process.
    build_ids: bool,
}

impl Normalizer {
    /// Create a new [`Normalizer`].
    pub fn new() -> Self {
        Builder::default().build()
    }

    /// Retrieve a [`Builder`] object for configurable construction of a
    /// [`Normalizer`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Normalize `addresses` belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. The `addrs` array has
    /// to be sorted in ascending order or an error will be returned. By
    /// providing a pre-sorted array the library does not have to sort
    /// internally, which will result in quicker normalization. If you
    /// don't have sorted addresses, use
    /// [`Normalizer::normalize_user_addrs`] instead.
    ///
    /// Unknown addresses are not normalized. They are reported as
    /// [`Unknown`][crate::normalize::Unknown] meta entries in the
    /// returned [`NormalizedUserAddrs`] object. The cause of an address
    /// to be unknown (and, hence, not normalized), could have a few
    /// reasons, including, but not limited to:
    /// - user error (if a bogus address was provided)
    /// - they belonged to an ELF object that has been unmapped since the
    ///   address was captured
    ///
    /// The process' ID should be provided in `pid`.
    ///
    /// Normalized addresses are reported in the exact same order in which the
    /// non-normalized ones were provided.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self)))]
    pub fn normalize_user_addrs_sorted(
        &self,
        addrs: &[Addr],
        pid: Pid,
    ) -> Result<NormalizedUserAddrs> {
        normalize_user_addrs_sorted_impl(addrs.iter().copied(), pid, self.build_ids)
    }


    /// Normalize `addresses` belonging to a process.
    ///
    /// Normalize all `addrs` in a given process. Contrary to
    /// [`Normalizer::normalize_user_addrs_sorted`], the provided `addrs` array
    /// does not have to be sorted, but otherwise the functions behave
    /// identically. If you do happen to know that `addrs` is sorted, using
    /// [`Normalizer::normalize_user_addrs_sorted`] instead will result in
    /// slightly faster normalization.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self)))]
    pub fn normalize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<NormalizedUserAddrs> {
        util::with_ordered_elems(
            addrs,
            |normalized: &mut NormalizedUserAddrs| normalized.addrs.as_mut_slice(),
            |sorted_addrs| normalize_user_addrs_sorted_impl(sorted_addrs, pid, self.build_ids),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::transmute;
    use std::path::Path;
    use std::path::PathBuf;

    use test_log::test;

    use crate::elf::ElfParser;
    use crate::inspect::FindAddrOpts;
    use crate::inspect::SymType;
    use crate::mmap::Mmap;
    use crate::normalize::buildid::read_elf_build_id;
    use crate::normalize::ApkElf;
    use crate::normalize::Elf;
    use crate::normalize::Unknown;
    use crate::normalize::UserAddrMeta;
    use crate::zip;


    /// Check that we detect unsorted input addresses.
    #[test]
    fn user_address_normalization_unsorted() {
        let mut addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
        ];
        let () = addrs.sort();
        let () = addrs.swap(0, 1);

        let normalizer = Normalizer::new();
        let err = normalizer
            .normalize_user_addrs_sorted(addrs.as_slice(), Pid::Slf)
            .unwrap_err();
        assert!(err.to_string().contains("are not sorted"), "{err}");
    }

    /// Check that we handle unknown addresses as expected.
    #[test]
    fn user_address_normalization_unknown() {
        // The very first page of the address space should never be
        // mapped, so use addresses from there.
        let addrs = [0x500 as Addr, 0x600 as Addr];

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted(addrs.as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 2);
        assert_eq!(norm_addrs.meta.len(), 1);
        assert_eq!(norm_addrs.meta[0], Unknown::default().into());
        assert_eq!(norm_addrs.addrs[0].1, 0);
        assert_eq!(norm_addrs.addrs[1].1, 0);
    }

    /// Check that we can normalize user addresses.
    #[test]
    fn user_address_normalization() {
        let addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
            user_address_normalization_unknown as Addr,
            user_address_normalization as Addr,
            Mmap::map as Addr,
        ];

        let (errno_idx, _) = addrs
            .iter()
            .enumerate()
            .find(|(_idx, addr)| **addr == libc::__errno_location as Addr)
            .unwrap();

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs(addrs.as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 6);

        let addrs = &norm_addrs.addrs;
        let meta = &norm_addrs.meta;
        assert_eq!(meta.len(), 2);

        let errno_meta_idx = addrs[errno_idx].1;
        assert!(meta[errno_meta_idx]
            .elf()
            .unwrap()
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("libc.so"));
    }

    /// Check that we can normalize user addresses in our own shared object.
    #[test]
    fn user_address_normalization_custom_so() {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");

        let mmap = Mmap::builder().exec().open(test_so).unwrap();
        // Look up the address of the `the_answer` function inside of the shared
        // object.
        let elf_parser = ElfParser::from_mmap(mmap.clone());
        let opts = FindAddrOpts {
            sym_type: SymType::Function,
            ..Default::default()
        };
        let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
        // There is only one symbol with this address in there.
        assert_eq!(syms.len(), 1);
        let sym = syms.first().unwrap();

        let the_answer_addr = unsafe { mmap.as_ptr().add(sym.addr) };
        // Now just double check that everything worked out and the function
        // is actually where it was meant to be.
        let the_answer_fn =
            unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
        let answer = the_answer_fn();
        assert_eq!(answer, 42);

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 1);
        assert_eq!(norm_addrs.meta.len(), 1);

        let norm_addr = norm_addrs.addrs[0];
        assert_eq!(norm_addr.0, sym.addr);
        let meta = &norm_addrs.meta[norm_addr.1];
        let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let expected_elf = Elf {
            build_id: Some(read_elf_build_id(&so_path).unwrap().unwrap()),
            path: so_path,
            _non_exhaustive: (),
        };
        assert_eq!(meta, &UserAddrMeta::Elf(expected_elf));
    }

    /// Check that we can normalize addresses in our own shared object inside a
    /// zip archive.
    #[test]
    fn user_address_normalization_custom_so_in_zip() {
        fn test(so_name: &str) {
            let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("test.zip");

            let mmap = Mmap::builder().exec().open(&test_zip).unwrap();
            let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
            let so = archive
                .entries()
                .find_map(|entry| {
                    let entry = entry.unwrap();
                    (entry.path == Path::new(so_name)).then_some(entry)
                })
                .unwrap();

            let elf_mmap = mmap
                .constrain(so.data_offset..so.data_offset + so.data.len())
                .unwrap();

            // Look up the address of the `the_answer` function inside of the shared
            // object.
            let elf_parser = ElfParser::from_mmap(elf_mmap.clone());
            let opts = FindAddrOpts {
                sym_type: SymType::Function,
                ..Default::default()
            };
            let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
            // There is only one symbol with this address in there.
            assert_eq!(syms.len(), 1);
            let sym = syms.first().unwrap();

            let the_answer_addr = unsafe { elf_mmap.as_ptr().add(sym.addr) };
            // Now just double check that everything worked out and the function
            // is actually where it was meant to be.
            let the_answer_fn =
                unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
            let answer = the_answer_fn();
            assert_eq!(answer, 42);

            let normalizer = Normalizer::new();
            let norm_addrs = normalizer
                .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
                .unwrap();
            assert_eq!(norm_addrs.addrs.len(), 1);
            assert_eq!(norm_addrs.meta.len(), 1);

            let norm_addr = norm_addrs.addrs[0];
            assert_eq!(norm_addr.0, sym.addr);
            let meta = &norm_addrs.meta[norm_addr.1];
            let so_path = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(so_name);
            let expected = ApkElf {
                apk_path: test_zip,
                elf_path: PathBuf::from(so_name),
                elf_build_id: Some(read_elf_build_id(&so_path).unwrap().unwrap()),
                _non_exhaustive: (),
            };
            assert_eq!(meta, &UserAddrMeta::ApkElf(expected));
        }

        test("libtest-so.so");
        test("libtest-so-no-separate-code.so");
    }
}
