use std::path::Path;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::*;

pub const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
pub const APP_REG_NAME: &str = "NetSentinel";

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn format_exe_command(exe_path: &Path) -> String {
    format!("\"{}\"", exe_path.to_string_lossy())
}

pub fn get_current_exe_command() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Gagal mendeteksi path executable saat ini: {e}"))?;
    Ok(format_exe_command(&exe))
}

pub fn is_auto_start_enabled() -> bool {
    is_auto_start_enabled_custom(APP_REG_NAME)
}

pub fn is_auto_start_enabled_custom(val_name: &str) -> bool {
    let subkey = to_wide_null(RUN_KEY_PATH);
    let mut hkey: HKEY = 0;
    let ret = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if ret != ERROR_SUCCESS {
        return false;
    }

    let wide_name = to_wide_null(val_name);
    let mut val_type = 0u32;
    let mut data_size = 0u32;
    let q_ret = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut data_size,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }

    q_ret == ERROR_SUCCESS && val_type == REG_SZ && data_size > 0
}

#[allow(dead_code)]
pub fn get_auto_start_command() -> Option<String> {
    get_auto_start_command_custom(APP_REG_NAME)
}

pub fn get_auto_start_command_custom(val_name: &str) -> Option<String> {
    let subkey = to_wide_null(RUN_KEY_PATH);
    let mut hkey: HKEY = 0;
    let ret = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if ret != ERROR_SUCCESS {
        return None;
    }

    let wide_name = to_wide_null(val_name);
    let mut val_type = 0u32;
    let mut data_size = 0u32;
    let q_ret = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut data_size,
        )
    };
    if q_ret != ERROR_SUCCESS || val_type != REG_SZ || data_size == 0 {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let mut buffer = vec![0u8; data_size as usize];
    let read_ret = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            buffer.as_mut_ptr(),
            &mut data_size,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }

    if read_ret != ERROR_SUCCESS {
        return None;
    }

    let u16_slice = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr() as *const u16, (data_size as usize) / 2)
    };
    let s = String::from_utf16_lossy(u16_slice);
    Some(s.trim_end_matches('\0').to_string())
}

pub fn set_auto_start(enabled: bool) -> Result<(), String> {
    if enabled {
        let cmd = get_current_exe_command()?;
        set_auto_start_custom(APP_REG_NAME, &cmd)
    } else {
        disable_auto_start_custom(APP_REG_NAME)
    }
}

pub fn set_auto_start_custom(val_name: &str, cmd: &str) -> Result<(), String> {
    let subkey = to_wide_null(RUN_KEY_PATH);
    let mut hkey: HKEY = 0;
    let ret = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(format!("Gagal membuka kunci registry Run (error code {ret})"));
    }

    let wide_name = to_wide_null(val_name);
    let wide_data = to_wide_null(cmd);
    let byte_len = (wide_data.len() * std::mem::size_of::<u16>()) as u32;

    let set_ret = unsafe {
        RegSetValueExW(
            hkey,
            wide_name.as_ptr(),
            0,
            REG_SZ,
            wide_data.as_ptr() as *const u8,
            byte_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }

    if set_ret == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("Gagal menetapkan registry auto-start (error code {set_ret})"))
    }
}

pub fn disable_auto_start_custom(val_name: &str) -> Result<(), String> {
    let subkey = to_wide_null(RUN_KEY_PATH);
    let mut hkey: HKEY = 0;
    let ret = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(format!("Gagal membuka kunci registry Run (error code {ret})"));
    }

    let wide_name = to_wide_null(val_name);
    let del_ret = unsafe { RegDeleteValueW(hkey, wide_name.as_ptr()) };
    unsafe {
        RegCloseKey(hkey);
    }

    // ERROR_FILE_NOT_FOUND (2) is completely normal when disabling an entry that was not set
    if del_ret == ERROR_SUCCESS || del_ret == 2 {
        Ok(())
    } else {
        Err(format!("Gagal menghapus registry auto-start (error code {del_ret})"))
    }
}
