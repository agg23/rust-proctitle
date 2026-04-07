#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]

#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "bitrig",
))]
mod imp {
    use std::ffi::CString;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    /// Set a process title, or some approximation of it, if possible.
    pub fn set_title<T: AsRef<OsStr>>(title: T) {
        if let Ok(title) = CString::new(title.as_ref().to_owned().as_bytes()) {
            unsafe {
                setproctitle(b"-%s\0".as_ptr(), title.as_ptr());
            }
        }
    }

    #[link(name = "c")]
    extern "C" {
        fn setproctitle(fmt: *const u8, ...);
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use libc;
    use std::ffi::CString;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    /// Set a process title, or some approximation of it, if possible.
    pub fn set_title<T: AsRef<OsStr>>(title: T) {
        if let Ok(title) = CString::new(title.as_ref().to_owned().as_bytes()) {
            unsafe { libc::prctl(libc::PR_SET_NAME, title.as_ptr(), 0, 0, 0) };
        }
    }

    #[test]
    fn set_title_sets_name() {
        use libc;
        set_title("abcdefghijklmnopqrstu");

        let mut buf = [0u8; 16];
        unsafe { libc::prctl(libc::PR_GET_NAME, buf.as_mut_ptr(), 0, 0, 0) };
        assert_eq!(&buf, b"abcdefghijklmno\0");
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Once;

    use core_foundation::base::TCFType;
    use core_foundation::bundle::CFBundle;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFTypeRef, OSStatus};
    use core_foundation_sys::bundle::CFBundleGetDataPointerForName;
    use core_foundation_sys::dictionary::{
        CFDictionaryAddValue, CFDictionaryCreateMutableCopy, CFDictionaryRef,
        CFMutableDictionaryRef,
    };
    use core_foundation_sys::string::CFStringRef;

    /// Session ID constant for the default session.
    #[allow(non_upper_case_globals)]
    const kLSDefaultSessionID: i32 = -2;

    // Function pointer types for the private Launch Services APIs.
    type LSGetCurrentApplicationASNFn = unsafe extern "C" fn() -> CFTypeRef;
    type LSSetApplicationInformationItemFn = unsafe extern "C" fn(
        i32,                  // session ID
        CFTypeRef,            // ASN
        CFStringRef,          // key
        CFStringRef,          // value
        *mut CFDictionaryRef, // out
    ) -> OSStatus;
    type LSApplicationCheckInFn = unsafe extern "C" fn(i32, CFDictionaryRef) -> CFDictionaryRef;
    type LSSetApplicationLaunchServicesServerConnectionStatusFn =
        unsafe extern "C" fn(u64, *const std::ffi::c_void);

    /// Resolved Launch Services symbols needed to set the process title
    /// in Activity Monitor.
    struct LaunchServices {
        _handle: *mut std::ffi::c_void,
        get_current_asn: LSGetCurrentApplicationASNFn,
        set_information_item: LSSetApplicationInformationItemFn,
        application_check_in: LSApplicationCheckInFn,
        set_server_connection_status: LSSetApplicationLaunchServicesServerConnectionStatusFn,
        display_name_key: CFStringRef,
    }

    // LaunchServices holds raw pointers but they are function pointers and a
    // global data pointer from a framework that lives for the process lifetime.
    unsafe impl Send for LaunchServices {}
    unsafe impl Sync for LaunchServices {}

    impl LaunchServices {
        /// Attempt to resolve all required private Launch Services symbols.
        /// Returns `None` if any symbol cannot be found.
        fn init() -> Option<Self> {
            // dlopen ApplicationServices to ensure the Launch Services bundle is loaded.
            let handle = unsafe {
                libc::dlopen(
                    b"/System/Library/Frameworks/ApplicationServices.framework/Versions/Current/ApplicationServices\0"
                        .as_ptr() as *const _,
                    libc::RTLD_LAZY | libc::RTLD_LOCAL,
                )
            };
            if handle.is_null() {
                return None;
            }

            let ls_bundle =
                CFBundle::bundle_with_identifier(CFString::new("com.apple.LaunchServices"))?;

            // Resolve private function pointers (note the underscore prefix).
            let get_current_asn: LSGetCurrentApplicationASNFn = unsafe {
                let ptr = ls_bundle
                    .function_pointer_for_name(CFString::new("_LSGetCurrentApplicationASN"));
                if ptr.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                std::mem::transmute(ptr)
            };

            let set_information_item: LSSetApplicationInformationItemFn = unsafe {
                let ptr = ls_bundle
                    .function_pointer_for_name(CFString::new("_LSSetApplicationInformationItem"));
                if ptr.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                std::mem::transmute(ptr)
            };

            let application_check_in: LSApplicationCheckInFn = unsafe {
                let ptr =
                    ls_bundle.function_pointer_for_name(CFString::new("_LSApplicationCheckIn"));
                if ptr.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                std::mem::transmute(ptr)
            };

            let set_server_connection_status: LSSetApplicationLaunchServicesServerConnectionStatusFn = unsafe {
                let ptr = ls_bundle.function_pointer_for_name(CFString::new(
                    "_LSSetApplicationLaunchServicesServerConnectionStatus",
                ));
                if ptr.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                std::mem::transmute(ptr)
            };

            // Resolve the private data symbol for the display name key.
            let display_name_key: CFStringRef = unsafe {
                let ptr = CFBundleGetDataPointerForName(
                    ls_bundle.as_concrete_TypeRef(),
                    CFString::new("_kLSDisplayNameKey").as_concrete_TypeRef(),
                );
                if ptr.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                // The data pointer points to a CFStringRef variable.
                let key = *(ptr as *const CFStringRef);
                if key.is_null() {
                    libc::dlclose(handle);
                    return None;
                }
                key
            };

            Some(LaunchServices {
                _handle: handle,
                get_current_asn,
                set_information_item,
                application_check_in,
                set_server_connection_status,
                display_name_key,
            })
        }

        /// Register this process with Launch Services and set the display name.
        fn set_title(&self, title: &CFString) -> bool {
            static CHECK_IN: Once = Once::new();

            CHECK_IN.call_once(|| {
                // Establish connection to the Launch Services server.
                unsafe {
                    (self.set_server_connection_status)(0, std::ptr::null());
                }

                // Get the main bundle's info dictionary and set LSUIElement=true
                // to prevent a Dock icon from appearing (required on macOS 15+).
                unsafe {
                    let main_bundle = core_foundation_sys::bundle::CFBundleGetMainBundle();
                    if !main_bundle.is_null() {
                        let info_dict =
                            core_foundation_sys::bundle::CFBundleGetInfoDictionary(main_bundle);
                        if !info_dict.is_null() {
                            let mutable_dict: CFMutableDictionaryRef =
                                CFDictionaryCreateMutableCopy(std::ptr::null(), 0, info_dict);
                            if !mutable_dict.is_null() {
                                let ls_ui_element_key = CFString::new("LSUIElement");
                                CFDictionaryAddValue(
                                    mutable_dict,
                                    ls_ui_element_key.as_concrete_TypeRef()
                                        as *const std::ffi::c_void,
                                    core_foundation_sys::number::kCFBooleanTrue
                                        as *const std::ffi::c_void,
                                );
                                (self.application_check_in)(
                                    kLSDefaultSessionID,
                                    mutable_dict as CFDictionaryRef,
                                );
                                core_foundation_sys::base::CFRelease(
                                    mutable_dict as *const std::ffi::c_void,
                                );
                            }
                        }
                    }
                }
            });

            // Get the current application's ASN and set its display name.
            unsafe {
                let asn = (self.get_current_asn)();
                if asn.is_null() {
                    return false;
                }

                let status = (self.set_information_item)(
                    kLSDefaultSessionID,
                    asn,
                    self.display_name_key,
                    title.as_concrete_TypeRef(),
                    std::ptr::null_mut(),
                );
                status == 0 // noErr
            }
        }
    }

    /// Set the thread name via pthread_setname_np (max 63 chars on macOS).
    fn set_thread_name(title: &[u8]) {
        let len = title.len().min(63);
        let mut buf = [0u8; 64];
        buf[..len].copy_from_slice(&title[..len]);
        // buf is already zero-terminated since it's initialized to zeros.
        unsafe {
            libc::pthread_setname_np(buf.as_ptr() as *const _);
        }
    }

    /// Set a process title, or some approximation of it, if possible.
    pub fn set_title<T: AsRef<OsStr>>(title: T) {
        let title_bytes = title.as_ref().as_bytes();

        // Try to set the Activity Monitor display name via Launch Services.
        // Use a static to cache the resolved symbols across calls.
        static INIT: Once = Once::new();
        static mut LS: Option<LaunchServices> = None;

        // Safety: LS is only written once inside INIT and then read-only.
        unsafe {
            INIT.call_once(|| {
                LS = LaunchServices::init();
            });

            if let Some(ref ls) = LS {
                // Convert to CFString. If the title contains interior NULs or
                // is otherwise invalid, we just skip the LS part.
                if let Ok(title_str) = std::str::from_utf8(title_bytes) {
                    let cf_title = CFString::new(title_str);
                    ls.set_title(&cf_title);
                }
            }
        }

        set_thread_name(title_bytes);
    }

    #[test]
    fn set_title_does_not_crash() {
        set_title("test: hello from proctitle");
        set_title("test: second call");
        set_title("");
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::Mutex;

    use lazy_static::lazy_static;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::synchapi::CreateEventW;
    use winapi::um::wincon::SetConsoleTitleW;
    use winapi::um::winnt::HANDLE;

    struct NamedHandle(HANDLE);
    unsafe impl Send for NamedHandle {}

    impl From<Vec<u16>> for NamedHandle {
        fn from(t: Vec<u16>) -> Self {
            assert!(t.ends_with(&[0]));

            Self(unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, t.as_ptr()) })
        }
    }

    impl Drop for NamedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    lazy_static! {
        static ref EVENT_HANDLE: Mutex<Option<NamedHandle>> = Mutex::new(None);
    }

    /// Set a process title, or some approximation of it, if possible.
    pub fn set_title<T: AsRef<OsStr>>(title: T) {
        // Windows doesn't appear to have a userspace mechanism to name the current
        // process.
        //
        // Try to set a console title, and in case we're not attached to one,
        // follow PostgreSQL's lead and create a named event handle that can be
        // found in Process Explorer, Process Hacker, etc.
        let mut t: Vec<u16> = title.as_ref().encode_wide().take(1024).collect();
        t.push(0);

        unsafe { SetConsoleTitleW(t.as_ptr()) };

        EVENT_HANDLE
            .lock()
            .expect("event handle lock")
            .replace(NamedHandle::from(t));
    }

    #[test]
    fn set_title_sets_console_title_and_makes_a_handle() {
        let title = "Pinkle, squirmy, blib, blab, blob";
        set_title(title);

        let mut t: Vec<u16> = std::ffi::OsString::from(title).encode_wide().collect();
        t.push(0);
        let mut buf = vec![0; t.len()];
        let len =
            unsafe { winapi::um::wincon::GetConsoleTitleW(buf.as_mut_ptr(), buf.len() as u32) };

        assert_eq!(len, title.len() as u32, "length mismatch");
        assert_eq!(buf, t, "buffer mismatch");
        assert!(
            EVENT_HANDLE.lock().unwrap().is_some(),
            "event handle missing"
        );
    }
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "bitrig",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
)))]
mod imp {
    use std::ffi::OsStr;

    /// Set a process title, or some approximation of it, if possible.
    pub fn set_title<T: AsRef<OsStr>>(_title: T) {}
}

pub use self::imp::*;

// This races against the SetConsoleTitle() tests on Windows
#[cfg(not(windows))]
#[test]
fn set_title_is_at_least_callable() {
    set_title("What was it like being a hamster?");
    set_title(String::from("It was better than being a chicken."));
    set_title(std::ffi::OsString::from(
        "Have you seen the size of an egg?",
    ));
}
