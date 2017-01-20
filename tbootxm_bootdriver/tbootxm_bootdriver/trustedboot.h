#include "measurement_util.h"

//
// Device Extension
//

typedef struct _DEVICE_EXTENSION {

	//
	// Back pointer to device object
	//

	PDEVICE_OBJECT DeviceObject;

	//
	// Target Device Object
	//

	PDEVICE_OBJECT TargetDeviceObject;

	//
	// Physical device object
	//
	PDEVICE_OBJECT PhysicalDeviceObject;

	//
	// RemoveLock prevents removal of a device while it is busy.
	//

	IO_REMOVE_LOCK RemoveLock;

	//
	// Disk number for reference in WMI
	//

	ULONG       DiskNumber;

	//
	// If device is enabled for counting always
	//

	LONG        EnabledAlways;

	//
	// Use to keep track of Volume info from ntddvol.h
	//

	WCHAR StorageManagerName[8];

	//
	// Disk performance counters
	// and locals used to compute counters
	//

	ULONG   Processors;
	PDISK_PERFORMANCE DiskCounters;    // per processor counters
	LARGE_INTEGER LastIdleClock;
	LONG QueueDepth;
	LONG CountersEnabled;

	//
	// must synchronize paging path notifications
	//
	KEVENT PagingPathCountEvent;
	LONG  PagingPathCount;

	//
	// Physical Device name or WMI Instance Name
	//

	UNICODE_STRING PhysicalDeviceName;
	WCHAR PhysicalDeviceNameBuffer[DISK_MAXSTR];

	//
	// Private context for using WmiLib
	//
	WMILIB_CONTEXT WmilibContext;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

DRIVER_UNLOAD tbootdriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH tbootdriverCreate;

DRIVER_DISPATCH tbootdriverSendToNextDriver;

DRIVER_ADD_DEVICE tbootdriverAddDevice;

#define DEVICE_EXTENSION_SIZE sizeof(DEVICE_EXTENSION)

void doMeasurement();