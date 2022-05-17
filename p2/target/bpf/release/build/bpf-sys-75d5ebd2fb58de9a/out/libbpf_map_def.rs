/* automatically generated by rust-bindgen 0.59.2 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_map_def {
    pub type_: ::std::os::raw::c_uint,
    pub key_size: ::std::os::raw::c_uint,
    pub value_size: ::std::os::raw::c_uint,
    pub max_entries: ::std::os::raw::c_uint,
    pub map_flags: ::std::os::raw::c_uint,
}
#[test]
fn bindgen_test_layout_bpf_map_def() {
    assert_eq!(
        ::std::mem::size_of::<bpf_map_def>(),
        20usize,
        concat!("Size of: ", stringify!(bpf_map_def))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_map_def>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_map_def))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_def>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_def),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_def>())).key_size as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_def),
            "::",
            stringify!(key_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_def>())).value_size as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_def),
            "::",
            stringify!(value_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_def>())).max_entries as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_def),
            "::",
            stringify!(max_entries)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_def>())).map_flags as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_def),
            "::",
            stringify!(map_flags)
        )
    );
}
