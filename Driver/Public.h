/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Driver,
    0xe31cb29c,0x726e,0x4d91,0xbd,0x4d,0xae,0x6d,0x14,0xab,0xcc,0x89);
// {e31cb29c-726e-4d91-bd4d-ae6d14abcc89}
