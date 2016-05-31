/*
*    main.c  --  SDSafeFormat
*
*    Copyright (C) 2016 - Peter Schultz (hp@hpes.dk)
*
*    SDSafeFormat is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*	 Inspired by Formatx example By Mark Russinovich, Systems Internal
*
*/

#include <windows.h>
#include <stdio.h>
#include "static_partion_types.h"
#include "static_media_type.h"

// remove warnings
extern int kbhit();
extern int getch();

typedef struct _disk { 
	char drive[MAX_PATH];
	char drive_root[MAX_PATH];
	char device_name[MAX_PATH];
	char volume_name[MAX_PATH];
	char device[20];
	char physical_drive[50];
	int  drive_type;
} DISK, *P_DISK;

// some quick fix definitions :-)
typedef struct _MBR_DRIVE_LAYOUT_INFORMATION {
	DWORD PartitionCount;
	DWORD Signature;
	PARTITION_INFORMATION PartitionEntry[4];
} MBR_DRIVE_LAYOUT_INFORMATION, *PMBR_DRIVE_LAYOUT_INFORMATION;

#define HIDDEN_SEC 8192
#define PART_TYPE 0x0c
#define SIGN 0x0a0b0c0d;

// ----------------------------------------
typedef struct {
	DWORD Lines;
	PCHAR Output;
} TEXTOUTPUT, *PTEXTOUTPUT;

typedef enum {
	PROGRESS,
	DONEWITHSTRUCTURE,
	UNKNOWN2,
	UNKNOWN3,
	UNKNOWN4,
	UNKNOWN5,
	INSUFFICIENTRIGHTS,
	UNKNOWN7,
	UNKNOWN8,
	UNKNOWN9,
	UNKNOWNA,
	DONE,
	UNKNOWNC,
	UNKNOWND,
	OUTPUT,
	STRUCTUREPROGRESS
} CALLBACKCOMMAND;

// FMIFS callback definition
typedef BOOLEAN(__stdcall *PFMIFSCALLBACK)(CALLBACKCOMMAND Command, DWORD SubAction, PVOID ActionInfo);

// Format command in FMIFS
typedef VOID(__stdcall *PFORMATEX)(PWCHAR DriveRoot,
	DWORD MediaFlag,
	PWCHAR Format,
	PWCHAR Label,
	BOOL QuickFormat,
	DWORD ClusterSize,
	PFMIFSCALLBACK Callback);
PFORMATEX   FormatEx;
// ------------------------------------------

// Prototypes
int lock_volume(HANDLE hdl, int b);
int set_drive_layout(HANDLE hdl, PDISK_GEOMETRY drive_geometry);
int create_disk(HANDLE hdl);
int dismount_volume(HANDLE hdl);
BOOLEAN __stdcall formatEx_callback(CALLBACKCOMMAND Command, DWORD Modifier, PVOID Argument);
BOOLEAN LoadFMIFSEntryPoints();

// Get drive info function protos
PDRIVE_LAYOUT_INFORMATION get_drive_layout(char *device);
PDISK_GEOMETRY get_drive_geometry(char *device);
int getDrives(P_DISK d[]);
int get_psysical_disk_name(char *device);

// Display function protos
void print_drive_layout(PDRIVE_LAYOUT_INFORMATION drv_layout_info);
void print_drive_geometry(PDISK_GEOMETRY drive_geometry);
void print_drive_info(P_DISK current_drive);
int disp_last_error_close( int rc, char *text, HANDLE hdl);
int disp_last_error(int rc, char *text);

int run_quertly = 0;

int main(int argc, char *argv[]) {
	int rc1, rc2, i;
	PDRIVE_LAYOUT_INFORMATION drv_layout_info;
	PDISK_GEOMETRY drive_geometry;
	P_DISK d1[26];
	P_DISK d2[26];
	P_DISK current_drive;
	HANDLE hdl;
	WCHAR  fdrive[20];
	memset(fdrive, 0, 20);

	if (argc == 2 && (argv[1][0] == 'q' || argv[1][0] == 'Q'))
		run_quertly = 1;


	if (LoadFMIFSEntryPoints())
		return disp_last_error(-1, "loading fmifs.dll FormatEx function.");

	for (i = 0; i < 26; i++) {
		d1[i] = (P_DISK)malloc(sizeof(DISK));
		d2[i] = (P_DISK)malloc(sizeof(DISK));
	}

	rc1 = getDrives((P_DISK *)&d1);
	printf("Insert the SD card to be formated.\n");
	if( !run_quertly)
		printf("If the SD card allready inserted, then remove it, hit a key and start SDSafeFormat again!\n");

	while (1) {
		Sleep(2000);
		rc2 = getDrives((P_DISK *)&d2);
		if (rc2 > rc1)
			break;
		if (kbhit()) {
			printf("\nFormat aborted\n");
			return -1;
		}
		printf(".");
	}
	for (i = 0; i < rc2; i++) {
		if (strcmp(d1[i]->drive, d2[i]->drive) != 0) {
			break;
		}
	}

	// select currect drive
	current_drive = d2[i];

	// Check if drive is removeable
	if (current_drive->drive_type != 2)
		return disp_last_error(-1, "Drive is not removeable");

	// TODO: Check if drive is writeprotected

	// OK. Now display all the drive info 
	print_drive_info(current_drive);
	drive_geometry = get_drive_geometry(current_drive->device);
	if (drive_geometry != NULL)
		print_drive_geometry(drive_geometry);

	drv_layout_info = get_drive_layout(current_drive->device);
	if (drv_layout_info != NULL)
		print_drive_layout(drv_layout_info);

	printf("\nRezize and format drive(y/N)?");
	if ((getchar() & 0xdf) != 0x59) {
		return -1;
	}

	// --------------------------------
	// OK. We now have to:
	// 1. Open a volume.
	// 2. Lock the volume.
	// 3. Initialize the volume.
	// 4. Unlock the volume.
	// 5. Close the volume handle.
	// 6. Format the volume.
	// --------------------------------
	// 1. Open a volume.
	if ((hdl = CreateFileA(current_drive->device, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL)) == INVALID_HANDLE_VALUE)
		return disp_last_error(GetLastError(), "invalid handle CreateFileA");

	// 2. Lock the volume.
	if (!lock_volume(hdl, 1))
		return disp_last_error_close(GetLastError(), "lock_volume", hdl);

	// 3. Initialize the volume.
	if ( !create_disk( hdl))
		return disp_last_error_close(GetLastError(), "create_disk", hdl);

	if ( !set_drive_layout(hdl, drive_geometry))
		return disp_last_error_close(GetLastError(), "set_drive_layout", hdl);

	// 4. Unlock the volume.
	if ( !lock_volume(hdl, 0))
		return disp_last_error_close(GetLastError(), "unlock_volume", hdl);

	// 5. Close the volume handle.
	CloseHandle(hdl);

	// 6. Format the volume.
	// RootDirectory, media_id, Format_type eg. FAT, Label, QuickFormat, ClusterSize, FormatExCallback
	MultiByteToWideChar(CP_ACP, 0, current_drive->drive, strlen(current_drive->drive), fdrive, sizeof(fdrive));
	FormatEx(fdrive, drive_geometry->MediaType, L"FAT32", L"SDSafeFmt", TRUE, 4096, formatEx_callback);

	printf("SDSafeFormat complete\n");
	printf("Hit Enter to close\n");
	if(!run_quertly)
		getch();
}
//----------------------------------------------------------------------
// FormatExCallback
//----------------------------------------------------------------------
BOOLEAN __stdcall formatEx_callback(CALLBACKCOMMAND Command, DWORD Modifier, PVOID Argument)
{
	PDWORD percent;
	PTEXTOUTPUT output;
	PBOOLEAN status;
	static createStructures = FALSE;

	// 
	// We get other types of commands, but we don't have to pay attention to them
	//
	switch (Command) {

	case PROGRESS:
		percent = (PDWORD)Argument;
		printf("%d percent completed.\r", *percent);
		break;

	case OUTPUT:
		output = (PTEXTOUTPUT)Argument;
		printf( "%s", output->Output);
		break;

	case DONE:
		status = (PBOOLEAN)Argument;
		if (*status == FALSE) {

			printf( "FormatEx was unable to complete successfully.\n\n");
		}
		break;
	}
	return TRUE;
}

// --------------------------------------------------------
BOOLEAN LoadFMIFSEntryPoints() {
	LoadLibraryA("fmifs.dll");
	FormatEx = (void *)GetProcAddress(GetModuleHandleA("fmifs.dll"), "FormatEx");
	if (!FormatEx)
		return -1;

	return 0;
}

// --------------------------------------------------------
// DeviceIoControl destructable funstions :-)
// --------------------------------------------------------
int lock_volume(HANDLE hdl, int b) {
	int f;
	unsigned long len;

	f = (b == 1) ? FSCTL_LOCK_VOLUME : FSCTL_UNLOCK_VOLUME;
	return DeviceIoControl(hdl, f, NULL, 0, NULL, 0, &len, NULL);
}

// --------------------------------------------------------
int dismount_volume(HANDLE hdl) {
	unsigned long len;

	return DeviceIoControl(hdl, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &len, NULL);
}

// --------------------------------------------------------
int create_disk(HANDLE hdl) {
	unsigned long len;
	CREATE_DISK dsk;
	CREATE_DISK_MBR dskMbr;

	dskMbr.Signature = 1234;
	dsk.PartitionStyle = PARTITION_STYLE_MBR;
	dsk.Mbr = dskMbr;

	return DeviceIoControl(hdl, IOCTL_DISK_CREATE_DISK, &dsk, sizeof(dsk), NULL, 0, &len, NULL);
}

// --------------------------------------------------------
int set_drive_layout(HANDLE hdl, PDISK_GEOMETRY drive_geometry) {
	int i;
	unsigned long len;
	MBR_DRIVE_LAYOUT_INFORMATION drive_layout_info;
	ULONGLONG disk_size;

	disk_size = drive_geometry->Cylinders.QuadPart * (ULONG)drive_geometry->TracksPerCylinder * (ULONG)drive_geometry->SectorsPerTrack * (ULONG)drive_geometry->BytesPerSector;

	drive_layout_info.PartitionCount = 4;
	drive_layout_info.Signature = SIGN;
	drive_layout_info.PartitionEntry[0].HiddenSectors = HIDDEN_SEC;
	drive_layout_info.PartitionEntry[0].BootIndicator = 0;
	drive_layout_info.PartitionEntry[0].PartitionNumber = 1;
	drive_layout_info.PartitionEntry[0].PartitionType = PART_TYPE;
	drive_layout_info.PartitionEntry[0].RecognizedPartition = 1;
	drive_layout_info.PartitionEntry[0].StartingOffset.QuadPart = HIDDEN_SEC * drive_geometry->BytesPerSector;
	drive_layout_info.PartitionEntry[0].RewritePartition = 1;
	drive_layout_info.PartitionEntry[0].PartitionLength.QuadPart = (disk_size) - (HIDDEN_SEC * drive_geometry->BytesPerSector);
	for (i = 1; i < 4; i++) {
		drive_layout_info.PartitionEntry[i].HiddenSectors = 0;
		drive_layout_info.PartitionEntry[i].BootIndicator = 0;
		drive_layout_info.PartitionEntry[i].PartitionNumber = i+1;
		drive_layout_info.PartitionEntry[i].PartitionType = 0;
		drive_layout_info.PartitionEntry[i].RecognizedPartition = 0;
		drive_layout_info.PartitionEntry[i].StartingOffset.QuadPart = 0;
		drive_layout_info.PartitionEntry[i].RewritePartition = 0;
		drive_layout_info.PartitionEntry[i].PartitionLength.QuadPart = 0;
	}

	return DeviceIoControl(hdl, IOCTL_DISK_SET_DRIVE_LAYOUT, &drive_layout_info, sizeof(MBR_DRIVE_LAYOUT_INFORMATION), NULL, 0, &len, NULL);
}

// --------------------------------------------------------
// Get drive info functions
// --------------------------------------------------------
PDISK_GEOMETRY get_drive_geometry(char *device) {

	HANDLE hdl = INVALID_HANDLE_VALUE;
	int rc;
	unsigned long len = 0;
	DISK_GEOMETRY *pdg = (PDISK_GEOMETRY) malloc(sizeof(DISK_GEOMETRY));

	if( (hdl = CreateFileA(device, 0,	FILE_SHARE_READ |FILE_SHARE_WRITE,	NULL, OPEN_EXISTING, 0,	NULL)) == INVALID_HANDLE_VALUE) {
		printf("\nCreate invalid handle %d. Aborting!\n", GetLastError());
		return NULL;
	}

	rc = DeviceIoControl(hdl, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, pdg, sizeof(*pdg), &len,	NULL);
	if (rc == 0) {
		printf("\nGET DRIVE GEOMETRY error %d. Aborting!\n", GetLastError());
		CloseHandle(hdl);
		return NULL;
	}

	CloseHandle(hdl);

	return pdg;
}

// --------------------------------------------------------
PDRIVE_LAYOUT_INFORMATION get_drive_layout(char *device) {
	int rc;
	unsigned long len;
	HANDLE hdl;
	char *buffer = malloc(4096);

	if ((hdl = CreateFileA(device, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\nCreate invalid handle %d. Aborting!\n", GetLastError());
		return NULL;
	}

	rc = DeviceIoControl(hdl, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0, (PPARTITION_INFORMATION)buffer, 4096, &len, NULL);
	if (rc == 0) {
		printf("\nGET DRIVE LAYOUT error %d. Aborting!\n", GetLastError());
		CloseHandle(hdl);
		return NULL;
	}

	CloseHandle(hdl);

	return (PDRIVE_LAYOUT_INFORMATION)buffer;
}

// --------------------------------------------------------
int getDrives( P_DISK d[]) {
	int    rc, len;
	int    ix = 0;
	HANDLE hdl;

	if ((hdl = FindFirstVolumeA(d[ix]->volume_name, sizeof(d[ix]->volume_name))) == INVALID_HANDLE_VALUE) {
		printf("FindFirstVolume failed with error code %d\n", GetLastError());
		return -1;
	}


	while (1) {
		d[ix]->drive_root[0] = '\0';
		rc = GetVolumePathNamesForVolumeNameA(d[ix]->volume_name, d[ix]->drive_root, sizeof(d[ix]->drive_root), &len);

		// Is there a drive name
		if (len > 1) {
			d[ix]->drive[0] = d[ix]->drive_root[0];
			d[ix]->drive[1] = d[ix]->drive_root[1];
			d[ix]->drive[2] = '\0';

			if ((len = QueryDosDeviceA(d[ix]->drive, d[ix]->device_name, sizeof(d[ix]->device_name))) <= 0) {
				printf("\nError %d in get DOS device name. Aborting!\n", GetLastError());
				printf("Hit Enter to close\n");
				getchar();
				return -1;
			}

			d[ix]->drive_type = GetDriveTypeA(d[ix]->drive_root);
			sprintf_s(d[ix]->device, 20, "\\\\.\\%s", d[ix]->drive);
			sprintf_s(d[ix]->physical_drive, 50, "\\\\.\\PhysicalDrive%d", get_psysical_disk_name(d[ix]->device));

			ix++;
		}

		if (!FindNextVolumeA(hdl, d[ix]->volume_name, sizeof(d[ix]->volume_name))) {
			if (GetLastError() != ERROR_NO_MORE_FILES) {
				printf("FindNextVolume failed with error code %d\n", GetLastError());
				printf("Hit Enter to close\n");
				getchar();
				return -1;
			}
			break;
		}
	}

	FindVolumeClose(hdl);

	return ix;

}

// --------------------------------------------------------
int get_psysical_disk_name(char *device) {
	int rc;
	unsigned long len;
	HANDLE hdl;
	VOLUME_DISK_EXTENTS voldsk;
	DISK_EXTENT dskExt[1];

	voldsk.Extents[0] = dskExt[0];

	if ((hdl = CreateFileA(device, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
		// Can easyly fail because its called on system drives
		// printf("\nGET_VOLUME_DISK_EXTENT Create invalid handle. Device=%s Error=%d. Aborting!\n", device, GetLastError());
		return -1;
	}

	rc = DeviceIoControl(hdl, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &voldsk, sizeof(voldsk), &len, NULL);
	if (rc == 0) {
		rc = GetLastError();
		CloseHandle(hdl);
		return rc*-1;
	}

	CloseHandle(hdl);

	return voldsk.Extents[0].DiskNumber;
}

// --------------------------------------------------------
// Display functions
// --------------------------------------------------------
void print_drive_info(P_DISK current_drive) {

	printf("\n\nDrive: %s\n", current_drive->drive);
	if (!run_quertly) {
		printf("Drive is removeable.\n"); //  current_drive->drive_type
		printf("Drive root: %s\n", current_drive->drive_root);
		printf("Device: %s\n", current_drive->device);
		printf("Device Name: %s\n", current_drive->device_name);
		printf("Volume Name: %s\n", current_drive->volume_name);
		printf("Physical Drive Name: %s\n", current_drive->physical_drive);
	}
}

// --------------------------------------------------------
void print_drive_layout(PDRIVE_LAYOUT_INFORMATION drv_layout_info) {

	unsigned long i;
	PPARTITION_INFORMATION part_info;

	if (!run_quertly) {
		printf("\rExisting partition info:\n");
		printf("\tSignature=0x%X\n", drv_layout_info->Signature);
		printf("\tPartitionCount=%d\n", drv_layout_info->PartitionCount);
		for (i = 0; i < drv_layout_info->PartitionCount; i++) {
			part_info = (PPARTITION_INFORMATION)&drv_layout_info->PartitionEntry[i];
			printf("\tPartition %d Info:\n", i);
			printf("\t\tPartitionType=0x%X: %s\n", part_info->PartitionType, parition_types[part_info->PartitionType]);
			if (part_info->PartitionType != 0) {
				printf("\t\tPartitionNumber=%ld\n", part_info->PartitionNumber);
				printf("\t\tStartingOffset=%I64d\n", part_info->StartingOffset.QuadPart);
				printf("\t\tPartitionLength=%I64d\n", part_info->PartitionLength.QuadPart);
				printf("\t\tHiddenSectors=%d\n", part_info->HiddenSectors);
				printf("\t\tBootIndicator=%d\n", part_info->BootIndicator);
				printf("\t\tRecognizedPartition=%d\n", part_info->RecognizedPartition);
				printf("\t\tRewritePartition=%d\n", part_info->RewritePartition);
			}
		}
	}
}

// --------------------------------------------------------
void print_drive_geometry(PDISK_GEOMETRY drive_geometry) {

	ULONGLONG disk_size;
	if (!run_quertly) {
		printf("Mediatype=0x%X: %s\n", drive_geometry->MediaType, media_type[drive_geometry->MediaType]);
		printf("Cylinders=%I64d\n", drive_geometry->Cylinders.QuadPart);
		printf("Tracks/cylinder=%ld\n", (ULONG)drive_geometry->TracksPerCylinder);
		printf("Sectors/track=%ld\n", (ULONG)drive_geometry->SectorsPerTrack);
		printf("Bytes/sector= %ld\n", (ULONG)drive_geometry->BytesPerSector);

		disk_size = drive_geometry->Cylinders.QuadPart * (ULONG)drive_geometry->TracksPerCylinder * (ULONG)drive_geometry->SectorsPerTrack * (ULONG)drive_geometry->BytesPerSector;
		printf("Disk size=%I64d Bytes or %.2f Gb\n", disk_size, (double)disk_size / (1024 * 1024 * 1024));
	}
}

// --------------------------------------------------------
int disp_last_error_close(int rc, char *text, HANDLE hdl) {
	CloseHandle(hdl);
	return disp_last_error(rc, text);
}

// --------------------------------------------------------
int disp_last_error(int rc, char *text) {
	printf("\nError %d in %s. Aborting!\n", rc, text);
	printf("Hit Enter to close\n");
	if( !run_quertly)
		getch();
	return -1;
}


// --- EOF --- EOF --- EOF --- EOF --- EOF --- EOF --- EOF --- EOF --- EOF ---