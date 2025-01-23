#include <ntddk.h>

VOID TriggerBSOD() {
    DbgPrint("Triggering BSOD...\n");
    KeBugCheckEx(0xDEADDEAD, 0, 0, 0, 0);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("BSOD Driver Unloading\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("BSOD Driver Loaded\n");

    DriverObject->DriverUnload = DriverUnload;  // Set unload routine

    // Now the BSOD is inside a function, making all code reachable before the crash
    TriggerBSOD();

    return STATUS_SUCCESS;  // This is technically unreachable, but required for a valid return type
}
