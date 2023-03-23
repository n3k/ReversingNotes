
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x0000000000000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x0000000000000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x0000000000000020
#define EFI_VARIABLE_APPEND_WRITE	0x0000000000000040

typedef void* PVOID;


typedef unsigned long long UINT64;

typedef long long INT64;

typedef unsigned int UINT32;

typedef int INT32;

typedef unsigned short UINT16;

typedef unsigned short CHAR16;

typedef short INT16;

typedef unsigned char BOOLEAN;

typedef unsigned char UINT8;

typedef char CHAR8;

typedef signed char INT8;


//This may be 64 bit in later phases, but in the PEI phase it is confirmed to be 32 bits
//typedef UINT64 UINTN;
typedef UINT32 UINTN;

typedef INT64 INTN;

extern UINT8 _VerifySizeofBOOLEAN[(sizeof(BOOLEAN) == (1)) / (sizeof(BOOLEAN) == (1))];
extern UINT8 _VerifySizeofINT8[(sizeof(INT8) == (1)) / (sizeof(INT8) == (1))];
extern UINT8 _VerifySizeofUINT8[(sizeof(UINT8) == (1)) / (sizeof(UINT8) == (1))];
extern UINT8 _VerifySizeofINT16[(sizeof(INT16) == (2)) / (sizeof(INT16) == (2))];
extern UINT8 _VerifySizeofUINT16[(sizeof(UINT16) == (2)) / (sizeof(UINT16) == (2))];
extern UINT8 _VerifySizeofINT32[(sizeof(INT32) == (4)) / (sizeof(INT32) == (4))];
extern UINT8 _VerifySizeofUINT32[(sizeof(UINT32) == (4)) / (sizeof(UINT32) == (4))];
extern UINT8 _VerifySizeofINT64[(sizeof(INT64) == (8)) / (sizeof(INT64) == (8))];
extern UINT8 _VerifySizeofUINT64[(sizeof(UINT64) == (8)) / (sizeof(UINT64) == (8))];
extern UINT8 _VerifySizeofCHAR8[(sizeof(CHAR8) == (1)) / (sizeof(CHAR8) == (1))];
extern UINT8 _VerifySizeofCHAR16[(sizeof(CHAR16) == (2)) / (sizeof(CHAR16) == (2))];
typedef struct {
UINT32 Data1;
UINT16 Data2;
UINT16 Data3;
UINT8 Data4[8];
} GUID;

typedef UINT64 PHYSICAL_ADDRESS;
struct _LIST_ENTRY {
LIST_ENTRY *ForwardLink;
LIST_ENTRY *BackLink;
};

typedef struct _LIST_ENTRY LIST_ENTRY;


typedef __builtin_va_list VA_LIST;
typedef UINTN *BASE_LIST;
typedef UINTN RETURN_STATUS;
typedef GUID EFI_GUID;

typedef RETURN_STATUS EFI_STATUS;

typedef void *EFI_HANDLE;

typedef void *EFI_EVENT;

typedef UINTN EFI_TPL;

typedef UINT64 EFI_LBA;

typedef UINT64 EFI_PHYSICAL_ADDRESS;

typedef UINT64 EFI_VIRTUAL_ADDRESS;
typedef struct {
UINT16 Year;
UINT8 Month;
UINT8 Day;
UINT8 Hour;
UINT8 Minute;
UINT8 Second;
UINT8 Pad1;
UINT32 Nanosecond;
INT16 TimeZone;
UINT8 Daylight;
UINT8 Pad2;
} EFI_TIME;

typedef struct {
UINT8 Addr[4];
} EFI_IPv4_ADDRESS;

typedef struct {
UINT8 Addr[16];
} EFI_IPv6_ADDRESS;

typedef struct {
UINT8 Addr[32];
} EFI_MAC_ADDRESS;

typedef union {
UINT32 Addr[4];
EFI_IPv4_ADDRESS v4;
EFI_IPv6_ADDRESS v6;
} EFI_IP_ADDRESS;

typedef struct {

UINT32 dwLength;

UINT16 wRevision;

UINT16 wCertificateType;

} WIN_CERTIFICATE;
typedef struct {
EFI_GUID HashType;
UINT8 PublicKey[256];
UINT8 Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct {

WIN_CERTIFICATE Hdr;

EFI_GUID CertType;

UINT8 CertData[1];
} WIN_CERTIFICATE_UEFI_GUID;
typedef struct {

WIN_CERTIFICATE Hdr;

EFI_GUID HashAlgorithm;
} WIN_CERTIFICATE_EFI_PKCS1_15;

extern EFI_GUID gEfiCertTypeRsa2048Sha256Guid;

typedef enum {

EfiReservedMemoryType,

EfiLoaderCode,

EfiLoaderData,

EfiBootServicesCode,

EfiBootServicesData,

EfiRuntimeServicesCode,

EfiRuntimeServicesData,

EfiConventionalMemory,

EfiUnusableMemory,

EfiACPIReclaimMemory,

EfiACPIMemoryNVS,

EfiMemoryMappedIO,

EfiMemoryMappedIOPortSpace,

EfiPalCode,
EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct {

UINT64 Signature;

UINT32 Revision;

UINT32 HeaderSize;

UINT32 CRC32;

UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct {

UINT64 MonotonicCount;
WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION;
typedef struct {

EFI_TIME TimeStamp;

WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

extern EFI_GUID gEfiPcAnsiGuid;
extern EFI_GUID gEfiVT100Guid;
extern EFI_GUID gEfiVT100PlusGuid;
extern EFI_GUID gEfiVTUTF8Guid;
extern EFI_GUID gEfiUartDevicePathGuid;
extern EFI_GUID gEfiSasDevicePathGuid;
#pragma pack(1)
typedef struct {
UINT8 Type;

UINT8 SubType;

UINT8 Length[2];

} EFI_DEVICE_PATH_PROTOCOL;

typedef EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 Function;

UINT8 Device;
} PCI_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 FunctionNumber;
} PCCARD_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 MemoryType;

EFI_PHYSICAL_ADDRESS StartingAddress;

EFI_PHYSICAL_ADDRESS EndingAddress;
} MEMMAP_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID Guid;

} VENDOR_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 ControllerNumber;
} CONTROLLER_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 HID;

UINT32 UID;
} ACPI_HID_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 HID;

UINT32 UID;

UINT32 CID;

} ACPI_EXTENDED_HID_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 ADR;

} ACPI_ADR_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 PrimarySecondary;

UINT8 SlaveMaster;

UINT16 Lun;
} ATAPI_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 Pun;

UINT16 Lun;
} SCSI_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 Reserved;

UINT64 WWN;

UINT64 Lun;
} FIBRECHANNEL_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 Reserved;

UINT8 WWN[8];

UINT8 Lun[8];
} FIBRECHANNELEX_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 Reserved;

UINT64 Guid;
} F1394_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 ParentPortNumber;

UINT8 InterfaceNumber;
} USB_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 VendorId;

UINT16 ProductId;

UINT8 DeviceClass;

UINT8 DeviceSubClass;

UINT8 DeviceProtocol;
} USB_CLASS_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 InterfaceNumber;

UINT16 VendorId;

UINT16 ProductId;

} USB_WWID_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 Lun;
} DEVICE_LOGICAL_UNIT_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 HBAPortNumber;

UINT16 PortMultiplierPortNumber;

UINT16 Lun;
} SATA_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 Tid;
} I2O_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_MAC_ADDRESS MacAddress;

UINT8 IfType;
} MAC_ADDR_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_IPv4_ADDRESS LocalIpAddress;

EFI_IPv4_ADDRESS RemoteIpAddress;

UINT16 LocalPort;

UINT16 RemotePort;

UINT16 Protocol;

BOOLEAN StaticIpAddress;

EFI_IPv4_ADDRESS GatewayIpAddress;

EFI_IPv4_ADDRESS SubnetMask;
} IPv4_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_IPv6_ADDRESS LocalIpAddress;

EFI_IPv6_ADDRESS RemoteIpAddress;

UINT16 LocalPort;

UINT16 RemotePort;

UINT16 Protocol;

UINT8 IpAddressOrigin;

UINT8 PrefixLength;

EFI_IPv6_ADDRESS GatewayIpAddress;
} IPv6_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;
UINT32 ResourceFlags;

UINT8 PortGid[16];

UINT64 ServiceId;

UINT64 TargetPortId;

UINT64 DeviceId;
} INFINIBAND_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 Reserved;

UINT64 BaudRate;

UINT8 DataBits;
UINT8 Parity;

UINT8 StopBits;
} UART_DEVICE_PATH;

typedef VENDOR_DEVICE_PATH VENDOR_DEFINED_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID Guid;

UINT32 FlowControlMap;
} UART_FLOW_CONTROL_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID Guid;

UINT32 Reserved;

UINT64 SasAddress;

UINT64 Lun;

UINT16 DeviceTopology;

UINT16 RelativeTargetPort;
} SAS_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT8 SasAddress[8];

UINT8 Lun[8];

UINT16 DeviceTopology;

UINT16 RelativeTargetPort;
} SASEX_DEVICE_PATH;

typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 NetworkProtocol;

UINT16 LoginOption;

UINT64 Lun;

UINT16 TargetPortalGroupTag;

} ISCSI_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 VlanId;
} VLAN_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 PartitionNumber;

UINT64 PartitionStart;

UINT64 PartitionSize;

UINT8 Signature[16];

UINT8 MBRType;

UINT8 SignatureType;
} HARDDRIVE_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT32 BootEntry;

UINT64 PartitionStart;

UINT64 PartitionSize;
} CDROM_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

CHAR16 PathName[1];
} FILEPATH_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID Protocol;
} MEDIA_PROTOCOL_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID FvFileName;
} MEDIA_FW_VOL_FILEPATH_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

EFI_GUID FvName;
} MEDIA_FW_VOL_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;
UINT32 Reserved;
UINT64 StartingOffset;
UINT64 EndingOffset;
} MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH;
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;

UINT16 DeviceType;

UINT16 StatusFlag;

CHAR8 String[1];
} BBS_BBS_DEVICE_PATH;
typedef union {
EFI_DEVICE_PATH_PROTOCOL DevPath;
PCI_DEVICE_PATH Pci;
PCCARD_DEVICE_PATH PcCard;
MEMMAP_DEVICE_PATH MemMap;
VENDOR_DEVICE_PATH Vendor;

CONTROLLER_DEVICE_PATH Controller;
ACPI_HID_DEVICE_PATH Acpi;
ACPI_EXTENDED_HID_DEVICE_PATH ExtendedAcpi;
ACPI_ADR_DEVICE_PATH AcpiAdr;

ATAPI_DEVICE_PATH Atapi;
SCSI_DEVICE_PATH Scsi;
ISCSI_DEVICE_PATH Iscsi;
FIBRECHANNEL_DEVICE_PATH FibreChannel;
FIBRECHANNELEX_DEVICE_PATH FibreChannelEx;

F1394_DEVICE_PATH F1394;
USB_DEVICE_PATH Usb;
SATA_DEVICE_PATH Sata;
USB_CLASS_DEVICE_PATH UsbClass;
USB_WWID_DEVICE_PATH UsbWwid;
DEVICE_LOGICAL_UNIT_DEVICE_PATH LogicUnit;
I2O_DEVICE_PATH I2O;
MAC_ADDR_DEVICE_PATH MacAddr;
IPv4_DEVICE_PATH Ipv4;
IPv6_DEVICE_PATH Ipv6;
VLAN_DEVICE_PATH Vlan;
INFINIBAND_DEVICE_PATH InfiniBand;
UART_DEVICE_PATH Uart;
UART_FLOW_CONTROL_DEVICE_PATH UartFlowControl;
SAS_DEVICE_PATH Sas;
SASEX_DEVICE_PATH SasEx;
HARDDRIVE_DEVICE_PATH HardDrive;
CDROM_DEVICE_PATH CD;

FILEPATH_DEVICE_PATH FilePath;
MEDIA_PROTOCOL_DEVICE_PATH MediaProtocol;

MEDIA_FW_VOL_DEVICE_PATH FirmwareVolume;
MEDIA_FW_VOL_FILEPATH_DEVICE_PATH FirmwareFile;
MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH Offset;

BBS_BBS_DEVICE_PATH Bbs;
} EFI_DEV_PATH;

typedef union {
EFI_DEVICE_PATH_PROTOCOL *DevPath;
PCI_DEVICE_PATH *Pci;
PCCARD_DEVICE_PATH *PcCard;
MEMMAP_DEVICE_PATH *MemMap;
VENDOR_DEVICE_PATH *Vendor;

CONTROLLER_DEVICE_PATH *Controller;
ACPI_HID_DEVICE_PATH *Acpi;
ACPI_EXTENDED_HID_DEVICE_PATH *ExtendedAcpi;
ACPI_ADR_DEVICE_PATH *AcpiAdr;

ATAPI_DEVICE_PATH *Atapi;
SCSI_DEVICE_PATH *Scsi;
ISCSI_DEVICE_PATH *Iscsi;
FIBRECHANNEL_DEVICE_PATH *FibreChannel;
FIBRECHANNELEX_DEVICE_PATH *FibreChannelEx;

F1394_DEVICE_PATH *F1394;
USB_DEVICE_PATH *Usb;
SATA_DEVICE_PATH *Sata;
USB_CLASS_DEVICE_PATH *UsbClass;
USB_WWID_DEVICE_PATH *UsbWwid;
DEVICE_LOGICAL_UNIT_DEVICE_PATH *LogicUnit;
I2O_DEVICE_PATH *I2O;
MAC_ADDR_DEVICE_PATH *MacAddr;
IPv4_DEVICE_PATH *Ipv4;
IPv6_DEVICE_PATH *Ipv6;
VLAN_DEVICE_PATH *Vlan;
INFINIBAND_DEVICE_PATH *InfiniBand;
UART_DEVICE_PATH *Uart;
UART_FLOW_CONTROL_DEVICE_PATH *UartFlowControl;
SAS_DEVICE_PATH *Sas;
SASEX_DEVICE_PATH *SasEx;
HARDDRIVE_DEVICE_PATH *HardDrive;
CDROM_DEVICE_PATH *CD;

FILEPATH_DEVICE_PATH *FilePath;
MEDIA_PROTOCOL_DEVICE_PATH *MediaProtocol;

MEDIA_FW_VOL_DEVICE_PATH *FirmwareVolume;
MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *FirmwareFile;
MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH *Offset;

BBS_BBS_DEVICE_PATH *Bbs;
UINT8 *Raw;
} EFI_DEV_PATH_PTR;

#pragma pack()

extern EFI_GUID gEfiDevicePathProtocolGuid;

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL SIMPLE_INPUT_INTERFACE;

typedef struct {
UINT16 ScanCode;
CHAR16 UnicodeChar;
} EFI_INPUT_KEY;
typedef
EFI_STATUS
( *EFI_INPUT_RESET)(
EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_INPUT_READ_KEY)(
EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
EFI_INPUT_KEY *Key
);

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
EFI_INPUT_RESET Reset;
EFI_INPUT_READ_KEY ReadKeyStroke;

EFI_EVENT WaitForKey;
};

extern EFI_GUID gEfiSimpleTextInProtocolGuid;

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;
typedef
EFI_STATUS
( *EFI_INPUT_RESET_EX)(
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
BOOLEAN ExtendedVerification
);

typedef UINT8 EFI_KEY_TOGGLE_STATE;

typedef struct _EFI_KEY_STATE {

UINT32 KeyShiftState;

EFI_KEY_TOGGLE_STATE KeyToggleState;
} EFI_KEY_STATE;

typedef struct {

EFI_INPUT_KEY Key;

EFI_KEY_STATE KeyState;
} EFI_KEY_DATA;
typedef
EFI_STATUS
( *EFI_INPUT_READ_KEY_EX)(
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
EFI_KEY_DATA *KeyData
);
typedef
EFI_STATUS
( *EFI_SET_STATE)(
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
EFI_KEY_TOGGLE_STATE *KeyToggleState
);

typedef
EFI_STATUS
( *EFI_KEY_NOTIFY_FUNCTION)(
EFI_KEY_DATA *KeyData
);
typedef
EFI_STATUS
( *EFI_REGISTER_KEYSTROKE_NOTIFY)(
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
EFI_KEY_DATA *KeyData,
EFI_KEY_NOTIFY_FUNCTION KeyNotificationFunction,
EFI_HANDLE *NotifyHandle
);
typedef
EFI_STATUS
( *EFI_UNREGISTER_KEYSTROKE_NOTIFY)(
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
EFI_HANDLE NotificationHandle
);
struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL{
EFI_INPUT_RESET_EX Reset;
EFI_INPUT_READ_KEY_EX ReadKeyStrokeEx;

EFI_EVENT WaitForKeyEx;
EFI_SET_STATE SetState;
EFI_REGISTER_KEYSTROKE_NOTIFY RegisterKeyNotify;
EFI_UNREGISTER_KEYSTROKE_NOTIFY UnregisterKeyNotify;
};

extern EFI_GUID gEfiSimpleTextInputExProtocolGuid;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL SIMPLE_TEXT_OUTPUT_INTERFACE;
typedef
EFI_STATUS
( *EFI_TEXT_RESET)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_TEXT_STRING)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
CHAR16 *String
);
typedef
EFI_STATUS
( *EFI_TEXT_TEST_STRING)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
CHAR16 *String
);
typedef
EFI_STATUS
( *EFI_TEXT_QUERY_MODE)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
UINTN ModeNumber,
UINTN *Columns,
UINTN *Rows
);
typedef
EFI_STATUS
( *EFI_TEXT_SET_MODE)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
UINTN ModeNumber
);
typedef
EFI_STATUS
( *EFI_TEXT_SET_ATTRIBUTE)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
UINTN Attribute
);
typedef
EFI_STATUS
( *EFI_TEXT_CLEAR_SCREEN)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_TEXT_SET_CURSOR_POSITION)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
UINTN Column,
UINTN Row
);
typedef
EFI_STATUS
( *EFI_TEXT_ENABLE_CURSOR)(
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
BOOLEAN Visible
);

typedef struct {

INT32 MaxMode;
INT32 Mode;

INT32 Attribute;

INT32 CursorColumn;

INT32 CursorRow;

BOOLEAN CursorVisible;
} EFI_SIMPLE_TEXT_OUTPUT_MODE;

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
EFI_TEXT_RESET Reset;

EFI_TEXT_STRING OutputString;
EFI_TEXT_TEST_STRING TestString;

EFI_TEXT_QUERY_MODE QueryMode;
EFI_TEXT_SET_MODE SetMode;
EFI_TEXT_SET_ATTRIBUTE SetAttribute;

EFI_TEXT_CLEAR_SCREEN ClearScreen;
EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
EFI_TEXT_ENABLE_CURSOR EnableCursor;

EFI_SIMPLE_TEXT_OUTPUT_MODE *Mode;
};

extern EFI_GUID gEfiSimpleTextOutProtocolGuid;

typedef enum {

AllocateAnyPages,

AllocateMaxAddress,

AllocateAddress,

MaxAllocateType
} EFI_ALLOCATE_TYPE;
typedef struct {

UINT32 Type;

EFI_PHYSICAL_ADDRESS PhysicalStart;

EFI_VIRTUAL_ADDRESS VirtualStart;

UINT64 NumberOfPages;

UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;
typedef
EFI_STATUS
( *EFI_ALLOCATE_PAGES)(
EFI_ALLOCATE_TYPE Type,
EFI_MEMORY_TYPE MemoryType,
UINTN Pages,
EFI_PHYSICAL_ADDRESS *Memory
);
typedef
EFI_STATUS
( *EFI_FREE_PAGES)(
EFI_PHYSICAL_ADDRESS Memory,
UINTN Pages
);
typedef
EFI_STATUS
( *EFI_GET_MEMORY_MAP)(
UINTN *MemoryMapSize,
EFI_MEMORY_DESCRIPTOR *MemoryMap,
UINTN *MapKey,
UINTN *DescriptorSize,
UINT32 *DescriptorVersion
);
typedef
EFI_STATUS
( *EFI_ALLOCATE_POOL)(
EFI_MEMORY_TYPE PoolType,
UINTN Size,
void **Buffer
);
typedef
EFI_STATUS
( *EFI_FREE_POOL)(
void *Buffer
);
typedef
EFI_STATUS
( *EFI_SET_VIRTUAL_ADDRESS_MAP)(
UINTN MemoryMapSize,
UINTN DescriptorSize,
UINT32 DescriptorVersion,
EFI_MEMORY_DESCRIPTOR *VirtualMap
);
typedef
EFI_STATUS
( *EFI_CONNECT_CONTROLLER)(
EFI_HANDLE ControllerHandle,
EFI_HANDLE *DriverImageHandle,
EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath,
BOOLEAN Recursive
);
typedef
EFI_STATUS
( *EFI_DISCONNECT_CONTROLLER)(
EFI_HANDLE ControllerHandle,
EFI_HANDLE DriverImageHandle,
EFI_HANDLE ChildHandle
);
typedef
EFI_STATUS
( *EFI_CONVERT_POINTER)(
UINTN DebugDisposition,
void **Address
);
typedef
void
( *EFI_EVENT_NOTIFY)(
EFI_EVENT Event,
void *Context
);
typedef
EFI_STATUS
( *EFI_CREATE_EVENT)(
UINT32 Type,
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction,
void *NotifyContext,
EFI_EVENT *Event
);
typedef
EFI_STATUS
( *EFI_CREATE_EVENT_EX)(
UINT32 Type,
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction ,
void *NotifyContext ,
EFI_GUID *EventGroup ,
EFI_EVENT *Event
);

typedef enum {

TimerCancel,

TimerPeriodic,

TimerRelative
} EFI_TIMER_DELAY;
typedef
EFI_STATUS
( *EFI_SET_TIMER)(
EFI_EVENT Event,
EFI_TIMER_DELAY Type,
UINT64 TriggerTime
);
typedef
EFI_STATUS
( *EFI_SIGNAL_EVENT)(
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_WAIT_FOR_EVENT)(
UINTN NumberOfEvents,
EFI_EVENT *Event,
UINTN *Index
);
typedef
EFI_STATUS
( *EFI_CLOSE_EVENT)(
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_CHECK_EVENT)(
EFI_EVENT Event
);
typedef
EFI_TPL
( *EFI_RAISE_TPL)(
EFI_TPL NewTpl
);

typedef
void
( *EFI_RESTORE_TPL)(
EFI_TPL OldTpl
);
typedef
EFI_STATUS
( *EFI_GET_VARIABLE)(
CHAR16 *VariableName,
EFI_GUID *VendorGuid,
UINT32 *Attributes,
UINTN *DataSize,
void *Data
);
typedef
EFI_STATUS
( *EFI_GET_NEXT_VARIABLE_NAME)(
UINTN *VariableNameSize,
CHAR16 *VariableName,
EFI_GUID *VendorGuid
);
typedef
EFI_STATUS
( *EFI_SET_VARIABLE)(
CHAR16 *VariableName,
EFI_GUID *VendorGuid,
UINT32 Attributes,
UINTN DataSize,
void *Data
);

typedef struct {

UINT32 Resolution;

UINT32 Accuracy;

BOOLEAN SetsToZero;
} EFI_TIME_CAPABILITIES;
typedef
EFI_STATUS
( *EFI_GET_TIME)(
EFI_TIME *Time,
EFI_TIME_CAPABILITIES *Capabilities
);
typedef
EFI_STATUS
( *EFI_SET_TIME)(
EFI_TIME *Time
);
typedef
EFI_STATUS
( *EFI_GET_WAKEUP_TIME)(
BOOLEAN *Enabled,
BOOLEAN *Pending,
EFI_TIME *Time
);
typedef
EFI_STATUS
( *EFI_SET_WAKEUP_TIME)(
BOOLEAN Enable,
EFI_TIME *Time
);
typedef
EFI_STATUS
( *EFI_IMAGE_LOAD)(
BOOLEAN BootPolicy,
EFI_HANDLE ParentImageHandle,
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
void *SourceBuffer ,
UINTN SourceSize,
EFI_HANDLE *ImageHandle
);
typedef
EFI_STATUS
( *EFI_IMAGE_START)(
EFI_HANDLE ImageHandle,
UINTN *ExitDataSize,
CHAR16 **ExitData
);
typedef
EFI_STATUS
( *EFI_EXIT)(
EFI_HANDLE ImageHandle,
EFI_STATUS ExitStatus,
UINTN ExitDataSize,
CHAR16 *ExitData
);
typedef
EFI_STATUS
( *EFI_IMAGE_UNLOAD)(
EFI_HANDLE ImageHandle
);
typedef
EFI_STATUS
( *EFI_EXIT_BOOT_SERVICES)(
EFI_HANDLE ImageHandle,
UINTN MapKey
);
typedef
EFI_STATUS
( *EFI_STALL)(
UINTN Microseconds
);
typedef
EFI_STATUS
( *EFI_SET_WATCHDOG_TIMER)(
UINTN Timeout,
UINT64 WatchdogCode,
UINTN DataSize,
CHAR16 *WatchdogData
);

typedef enum {

EfiResetCold,

EfiResetWarm,

EfiResetShutdown
} EFI_RESET_TYPE;
typedef
void
( *EFI_RESET_SYSTEM)(
EFI_RESET_TYPE ResetType,
EFI_STATUS ResetStatus,
UINTN DataSize,
void *ResetData
);
typedef
EFI_STATUS
( *EFI_GET_NEXT_MONOTONIC_COUNT)(
UINT64 *Count
);
typedef
EFI_STATUS
( *EFI_GET_NEXT_HIGH_MONO_COUNT)(
UINT32 *HighCount
);
typedef
EFI_STATUS
( *EFI_CALCULATE_CRC32)(
void *Data,
UINTN DataSize,
UINT32 *Crc32
);
typedef
void
( *EFI_COPY_MEM)(
void *Destination,
void *Source,
UINTN Length
);
typedef
void
( *EFI_SET_MEM)(
void *Buffer,
UINTN Size,
UINT8 Value
);

typedef enum {

EFI_NATIVE_INTERFACE
} EFI_INTERFACE_TYPE;
typedef
EFI_STATUS
( *EFI_INSTALL_PROTOCOL_INTERFACE)(
EFI_HANDLE *Handle,
EFI_GUID *Protocol,
EFI_INTERFACE_TYPE InterfaceType,
void *Interface
);
typedef
EFI_STATUS
( *EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)(
EFI_HANDLE *Handle,
...
);
typedef
EFI_STATUS
( *EFI_REINSTALL_PROTOCOL_INTERFACE)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
void *OldInterface,
void *NewInterface
);
typedef
EFI_STATUS
( *EFI_UNINSTALL_PROTOCOL_INTERFACE)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
void *Interface
);
typedef
EFI_STATUS
( *EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)(
EFI_HANDLE Handle,
...
);
typedef
EFI_STATUS
( *EFI_HANDLE_PROTOCOL)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
void **Interface
);
typedef
EFI_STATUS
( *EFI_OPEN_PROTOCOL)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
void **Interface,
EFI_HANDLE AgentHandle,
EFI_HANDLE ControllerHandle,
UINT32 Attributes
);
typedef
EFI_STATUS
( *EFI_CLOSE_PROTOCOL)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
EFI_HANDLE AgentHandle,
EFI_HANDLE ControllerHandle
);

typedef struct {
EFI_HANDLE AgentHandle;
EFI_HANDLE ControllerHandle;
UINT32 Attributes;
UINT32 OpenCount;
} EFI_OPEN_PROTOCOL_INFORMATION_ENTRY;
typedef
EFI_STATUS
( *EFI_OPEN_PROTOCOL_INFORMATION)(
EFI_HANDLE Handle,
EFI_GUID *Protocol,
EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer,
UINTN *EntryCount
);
typedef
EFI_STATUS
( *EFI_PROTOCOLS_PER_HANDLE)(
EFI_HANDLE Handle,
EFI_GUID ***ProtocolBuffer,
UINTN *ProtocolBufferCount
);
typedef
EFI_STATUS
( *EFI_REGISTER_PROTOCOL_NOTIFY)(
EFI_GUID *Protocol,
EFI_EVENT Event,
void **Registration
);

typedef enum {

AllHandles,

ByRegisterNotify,

ByProtocol
} EFI_LOCATE_SEARCH_TYPE;
typedef
EFI_STATUS
( *EFI_LOCATE_HANDLE)(
EFI_LOCATE_SEARCH_TYPE SearchType,
EFI_GUID *Protocol,
void *SearchKey,
UINTN *BufferSize,
EFI_HANDLE *Buffer
);
typedef
EFI_STATUS
( *EFI_LOCATE_DEVICE_PATH)(
EFI_GUID *Protocol,
EFI_DEVICE_PATH_PROTOCOL **DevicePath,
EFI_HANDLE *Device
);
typedef
EFI_STATUS
( *EFI_INSTALL_CONFIGURATION_TABLE)(
EFI_GUID *Guid,
void *Table
);
typedef
EFI_STATUS
( *EFI_LOCATE_HANDLE_BUFFER)(
EFI_LOCATE_SEARCH_TYPE SearchType,
EFI_GUID *Protocol,
void *SearchKey,
UINTN *NoHandles,
EFI_HANDLE **Buffer
);
typedef
EFI_STATUS
( *EFI_LOCATE_PROTOCOL)(
EFI_GUID *Protocol,
void *Registration,
void **Interface
);

typedef struct {

UINT64 Length;
union {

EFI_PHYSICAL_ADDRESS DataBlock;

EFI_PHYSICAL_ADDRESS ContinuationPointer;
} Union;
} EFI_CAPSULE_BLOCK_DESCRIPTOR;

typedef struct {

EFI_GUID CapsuleGuid;

UINT32 HeaderSize;

UINT32 Flags;

UINT32 CapsuleImageSize;
} EFI_CAPSULE_HEADER;

typedef struct {

UINT32 CapsuleArrayNumber;

void* CapsulePtr[1];
} EFI_CAPSULE_TABLE;
typedef
EFI_STATUS
( *EFI_UPDATE_CAPSULE)(
EFI_CAPSULE_HEADER **CapsuleHeaderArray,
UINTN CapsuleCount,
EFI_PHYSICAL_ADDRESS ScatterGatherList
);
typedef
EFI_STATUS
( *EFI_QUERY_CAPSULE_CAPABILITIES)(
EFI_CAPSULE_HEADER **CapsuleHeaderArray,
UINTN CapsuleCount,
UINT64 *MaximumCapsuleSize,
EFI_RESET_TYPE *ResetType
);
typedef
EFI_STATUS
( *EFI_QUERY_VARIABLE_INFO)(
UINT32 Attributes,
UINT64 *MaximumVariableStorageSize,
UINT64 *RemainingVariableStorageSize,
UINT64 *MaximumVariableSize
);
typedef struct {

EFI_TABLE_HEADER Hdr;

EFI_GET_TIME GetTime;
EFI_SET_TIME SetTime;
EFI_GET_WAKEUP_TIME GetWakeupTime;
EFI_SET_WAKEUP_TIME SetWakeupTime;

EFI_SET_VIRTUAL_ADDRESS_MAP SetVirtualAddressMap;
EFI_CONVERT_POINTER ConvertPointer;

EFI_GET_VARIABLE GetVariable;
EFI_GET_NEXT_VARIABLE_NAME GetNextVariableName;
EFI_SET_VARIABLE SetVariable;

EFI_GET_NEXT_HIGH_MONO_COUNT GetNextHighMonotonicCount;
EFI_RESET_SYSTEM ResetSystem;

EFI_UPDATE_CAPSULE UpdateCapsule;
EFI_QUERY_CAPSULE_CAPABILITIES QueryCapsuleCapabilities;

EFI_QUERY_VARIABLE_INFO QueryVariableInfo;
} EFI_RUNTIME_SERVICES;
typedef struct {

EFI_TABLE_HEADER Hdr;

EFI_RAISE_TPL RaiseTPL;
EFI_RESTORE_TPL RestoreTPL;

EFI_ALLOCATE_PAGES AllocatePages;
EFI_FREE_PAGES FreePages;
EFI_GET_MEMORY_MAP GetMemoryMap;
EFI_ALLOCATE_POOL AllocatePool;
EFI_FREE_POOL FreePool;

EFI_CREATE_EVENT CreateEvent;
EFI_SET_TIMER SetTimer;
EFI_WAIT_FOR_EVENT WaitForEvent;
EFI_SIGNAL_EVENT SignalEvent;
EFI_CLOSE_EVENT CloseEvent;
EFI_CHECK_EVENT CheckEvent;

EFI_INSTALL_PROTOCOL_INTERFACE InstallProtocolInterface;
EFI_REINSTALL_PROTOCOL_INTERFACE ReinstallProtocolInterface;
EFI_UNINSTALL_PROTOCOL_INTERFACE UninstallProtocolInterface;
EFI_HANDLE_PROTOCOL HandleProtocol;
void *Reserved;
EFI_REGISTER_PROTOCOL_NOTIFY RegisterProtocolNotify;
EFI_LOCATE_HANDLE LocateHandle;
EFI_LOCATE_DEVICE_PATH LocateDevicePath;
EFI_INSTALL_CONFIGURATION_TABLE InstallConfigurationTable;

EFI_IMAGE_LOAD LoadImage;
EFI_IMAGE_START StartImage;
EFI_EXIT Exit;
EFI_IMAGE_UNLOAD UnloadImage;
EFI_EXIT_BOOT_SERVICES ExitBootServices;

EFI_GET_NEXT_MONOTONIC_COUNT GetNextMonotonicCount;
EFI_STALL Stall;
EFI_SET_WATCHDOG_TIMER SetWatchdogTimer;

EFI_CONNECT_CONTROLLER ConnectController;
EFI_DISCONNECT_CONTROLLER DisconnectController;

EFI_OPEN_PROTOCOL OpenProtocol;
EFI_CLOSE_PROTOCOL CloseProtocol;
EFI_OPEN_PROTOCOL_INFORMATION OpenProtocolInformation;

EFI_PROTOCOLS_PER_HANDLE ProtocolsPerHandle;
EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
EFI_LOCATE_PROTOCOL LocateProtocol;
EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES InstallMultipleProtocolInterfaces;
EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES UninstallMultipleProtocolInterfaces;

EFI_CALCULATE_CRC32 CalculateCrc32;

EFI_COPY_MEM CopyMem;
EFI_SET_MEM SetMem;
EFI_CREATE_EVENT_EX CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct {

EFI_GUID VendorGuid;

void *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {

EFI_TABLE_HEADER Hdr;

CHAR16 *FirmwareVendor;

UINT32 FirmwareRevision;

EFI_HANDLE ConsoleInHandle;

EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;

EFI_HANDLE ConsoleOutHandle;

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;

EFI_HANDLE StandardErrorHandle;

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;

EFI_RUNTIME_SERVICES *RuntimeServices;

EFI_BOOT_SERVICES *BootServices;

UINTN NumberOfTableEntries;

EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;
typedef
EFI_STATUS
( *EFI_IMAGE_ENTRY_POINT)(
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
typedef union {
struct {

UINT32 Revision : 8;

UINT32 ShiftPressed : 1;

UINT32 ControlPressed : 1;

UINT32 AltPressed : 1;

UINT32 LogoPressed : 1;

UINT32 MenuPressed : 1;

UINT32 SysReqPressed : 1;
UINT32 Reserved : 16;

UINT32 InputKeyCount : 2;
} Options;
UINT32 PackedValue;
} EFI_BOOT_KEY_DATA;

typedef struct {

EFI_BOOT_KEY_DATA KeyData;

UINT32 BootOptionCrc;

UINT16 BootOption;

} EFI_KEY_OPTION;
#pragma pack(1)
typedef void PXE_void;
typedef UINT8 PXE_UINT8;
typedef UINT16 PXE_UINT16;
typedef UINT32 PXE_UINT32;
typedef UINTN PXE_UINTN;

typedef UINT64 PXE_UINT64;

typedef PXE_UINT8 PXE_BOOL;

typedef PXE_UINT16 PXE_OPCODE;
typedef PXE_UINT16 PXE_OPFLAGS;
typedef PXE_UINT16 PXE_STATFLAGS;
typedef PXE_UINT16 PXE_STATCODE;
typedef PXE_UINT16 PXE_IFNUM;
typedef PXE_UINT16 PXE_CONTROL;
typedef PXE_UINT8 PXE_FRAME_TYPE;
typedef PXE_UINT32 PXE_IPV4;

typedef PXE_UINT32 PXE_IPV6[4];

typedef PXE_UINT8 PXE_MAC_ADDR[32];

typedef PXE_UINT8 PXE_IFTYPE;
typedef UINT16 PXE_MEDIA_PROTOCOL;
typedef struct s_pxe_hw_undi {
PXE_UINT32 Signature;
PXE_UINT8 Len;
PXE_UINT8 Fudge;
PXE_UINT8 Rev;
PXE_UINT8 IFcnt;
PXE_UINT8 MajorVer;
PXE_UINT8 MinorVer;
PXE_UINT16 reserved;
PXE_UINT32 Implementation;

} PXE_HW_UNDI;
typedef struct s_pxe_sw_undi {
PXE_UINT32 Signature;
PXE_UINT8 Len;
PXE_UINT8 Fudge;
PXE_UINT8 Rev;
PXE_UINT8 IFcnt;
PXE_UINT8 MajorVer;
PXE_UINT8 MinorVer;
PXE_UINT16 reserved1;
PXE_UINT32 Implementation;
PXE_UINT64 EntryPoint;
PXE_UINT8 reserved2[3];
PXE_UINT8 BusCnt;
PXE_UINT32 BusType[1];
} PXE_SW_UNDI;

typedef union u_pxe_undi {
PXE_HW_UNDI hw;
PXE_SW_UNDI sw;
} PXE_UNDI;
typedef struct s_pxe_cdb {
PXE_OPCODE OpCode;
PXE_OPFLAGS OpFlags;
PXE_UINT16 CPBsize;
PXE_UINT16 DBsize;
PXE_UINT64 CPBaddr;
PXE_UINT64 DBaddr;
PXE_STATCODE StatCode;
PXE_STATFLAGS StatFlags;
PXE_UINT16 IFnum;
PXE_CONTROL Control;
} PXE_CDB;

typedef union u_pxe_ip_addr {
PXE_IPV6 IPv6;
PXE_IPV4 IPv4;
} PXE_IP_ADDR;

typedef union pxe_device {

struct {

PXE_UINT32 BusType;

PXE_UINT16 Bus;
PXE_UINT8 Device;
PXE_UINT8 Function;
}
PCI, PCC;

} PXE_DEVICE;
typedef struct s_pxe_cpb_start_30 {
UINT64 Delay;
UINT64 Block;
UINT64 Virt2Phys;
UINT64 Mem_IO;
} PXE_CPB_START_30;

typedef struct s_pxe_cpb_start_31 {
UINT64 Delay;
UINT64 Block;
UINT64 Virt2Phys;
UINT64 Mem_IO;
UINT64 Map_Mem;
UINT64 UnMap_Mem;
UINT64 Sync_Mem;

UINT64 Unique_ID;
} PXE_CPB_START_31;
typedef struct s_pxe_db_get_init_info {
PXE_UINT32 MemoryRequired;

PXE_UINT32 FrameDataLen;

PXE_UINT32 LinkSpeeds[4];

PXE_UINT32 NvCount;

PXE_UINT16 NvWidth;

PXE_UINT16 MediaHeaderLen;

PXE_UINT16 HWaddrLen;

PXE_UINT16 MCastFilterCnt;
PXE_UINT16 TxBufCnt;
PXE_UINT16 TxBufSize;
PXE_UINT16 RxBufCnt;
PXE_UINT16 RxBufSize;

PXE_UINT8 IFtype;

PXE_UINT8 SupportedDuplexModes;

PXE_UINT8 SupportedLoopBackModes;
} PXE_DB_GET_INIT_INFO;
typedef struct s_pxe_pci_config_info {

UINT32 BusType;

UINT16 Bus;
UINT8 Device;
UINT8 Function;

union {
UINT8 Byte[256];
UINT16 Word[128];
UINT32 Dword[64];
} Config;
} PXE_PCI_CONFIG_INFO;

typedef struct s_pxe_pcc_config_info {

PXE_UINT32 BusType;

PXE_UINT16 Bus;
PXE_UINT8 Device;
PXE_UINT8 Function;

union {
PXE_UINT8 Byte[256];
PXE_UINT16 Word[128];
PXE_UINT32 Dword[64];
} Config;
} PXE_PCC_CONFIG_INFO;

typedef union u_pxe_db_get_config_info {
PXE_PCI_CONFIG_INFO pci;
PXE_PCC_CONFIG_INFO pcc;
} PXE_DB_GET_CONFIG_INFO;

typedef struct s_pxe_cpb_initialize {

PXE_UINT64 MemoryAddr;

PXE_UINT32 MemoryLength;

PXE_UINT32 LinkSpeed;
PXE_UINT16 TxBufCnt;
PXE_UINT16 TxBufSize;
PXE_UINT16 RxBufCnt;
PXE_UINT16 RxBufSize;

PXE_UINT8 DuplexMode;

PXE_UINT8 LoopBackMode;
} PXE_CPB_INITIALIZE;
typedef struct s_pxe_db_initialize {
PXE_UINT32 MemoryUsed;

PXE_UINT16 TxBufCnt;
PXE_UINT16 TxBufSize;
PXE_UINT16 RxBufCnt;
PXE_UINT16 RxBufSize;
} PXE_DB_INITIALIZE;

typedef struct s_pxe_cpb_receive_filters {

PXE_MAC_ADDR MCastList[8];
} PXE_CPB_RECEIVE_FILTERS;

typedef struct s_pxe_db_receive_filters {

PXE_MAC_ADDR MCastList[8];
} PXE_DB_RECEIVE_FILTERS;

typedef struct s_pxe_cpb_station_address {

PXE_MAC_ADDR StationAddr;
} PXE_CPB_STATION_ADDRESS;

typedef struct s_pxe_dpb_station_address {

PXE_MAC_ADDR StationAddr;

PXE_MAC_ADDR BroadcastAddr;

PXE_MAC_ADDR PermanentAddr;
} PXE_DB_STATION_ADDRESS;

typedef struct s_pxe_db_statistics {
PXE_UINT64 Supported;

PXE_UINT64 Data[64];
} PXE_DB_STATISTICS;
typedef struct s_pxe_cpb_mcast_ip_to_mac {

PXE_IP_ADDR IP;
} PXE_CPB_MCAST_IP_TO_MAC;

typedef struct s_pxe_db_mcast_ip_to_mac {

PXE_MAC_ADDR MAC;
} PXE_DB_MCAST_IP_TO_MAC;

typedef struct s_pxe_cpb_nvdata_sparse {

struct {

PXE_UINT32 Addr;

union {
PXE_UINT8 Byte;
PXE_UINT16 Word;
PXE_UINT32 Dword;
} Data;
} Item[128];
} PXE_CPB_NVDATA_SPARSE;

typedef union u_pxe_cpb_nvdata_bulk {

PXE_UINT8 Byte[128 << 2];

PXE_UINT16 Word[128 << 1];

PXE_UINT32 Dword[128];
} PXE_CPB_NVDATA_BULK;

typedef struct s_pxe_db_nvdata {

union {

PXE_UINT8 Byte[128 << 2];

PXE_UINT16 Word[128 << 1];

PXE_UINT32 Dword[128];
} Data;
} PXE_DB_NVDATA;

typedef struct s_pxe_db_get_status {

PXE_UINT32 RxFrameLen;

PXE_UINT32 reserved;

PXE_UINT64 TxBuffer[32];
} PXE_DB_GET_STATUS;

typedef struct s_pxe_cpb_fill_header {

PXE_MAC_ADDR SrcAddr;
PXE_MAC_ADDR DestAddr;

PXE_UINT64 MediaHeader;

PXE_UINT32 PacketLen;

PXE_UINT16 Protocol;

PXE_UINT16 MediaHeaderLen;
} PXE_CPB_FILL_HEADER;

typedef struct s_pxe_cpb_fill_header_fragmented {

PXE_MAC_ADDR SrcAddr;
PXE_MAC_ADDR DestAddr;

PXE_UINT32 PacketLen;

PXE_MEDIA_PROTOCOL Protocol;

PXE_UINT16 MediaHeaderLen;

PXE_UINT16 FragCnt;

PXE_UINT16 reserved;

struct {

PXE_UINT64 FragAddr;

PXE_UINT32 FragLen;

PXE_UINT32 reserved;
} FragDesc[16];
}
PXE_CPB_FILL_HEADER_FRAGMENTED;

typedef struct s_pxe_cpb_transmit {

PXE_UINT64 FrameAddr;

PXE_UINT32 DataLen;

PXE_UINT16 MediaheaderLen;

PXE_UINT16 reserved;
} PXE_CPB_TRANSMIT;

typedef struct s_pxe_cpb_transmit_fragments {

PXE_UINT32 FrameLen;

PXE_UINT16 MediaheaderLen;

PXE_UINT16 FragCnt;

struct {

PXE_UINT64 FragAddr;

PXE_UINT32 FragLen;

PXE_UINT32 reserved;
} FragDesc[16];
}
PXE_CPB_TRANSMIT_FRAGMENTS;

typedef struct s_pxe_cpb_receive {

PXE_UINT64 BufferAddr;

PXE_UINT32 BufferLen;

PXE_UINT32 reserved;
} PXE_CPB_RECEIVE;

typedef struct s_pxe_db_receive {

PXE_MAC_ADDR SrcAddr;
PXE_MAC_ADDR DestAddr;

PXE_UINT32 FrameLen;

PXE_MEDIA_PROTOCOL Protocol;

PXE_UINT16 MediaHeaderLen;

PXE_FRAME_TYPE Type;

PXE_UINT8 reserved[7];

} PXE_DB_RECEIVE;

#pragma pack()

#pragma pack(1)

typedef struct {

EFI_TABLE_HEADER Header;

EFI_LBA MyLBA;

EFI_LBA AlternateLBA;

EFI_LBA FirstUsableLBA;

EFI_LBA LastUsableLBA;

EFI_GUID DiskGUID;

EFI_LBA PartitionEntryLBA;

UINT32 NumberOfPartitionEntries;

UINT32 SizeOfPartitionEntry;

UINT32 PartitionEntryArrayCRC32;
} EFI_PARTITION_TABLE_HEADER;

typedef struct {

EFI_GUID PartitionTypeGUID;

EFI_GUID UniquePartitionGUID;

EFI_LBA StartingLBA;

EFI_LBA EndingLBA;
UINT64 Attributes;

CHAR16 PartitionName[36];
} EFI_PARTITION_ENTRY;

#pragma pack()

extern EFI_GUID gEfiHiiStandardFormGuid;

typedef void* EFI_HII_HANDLE;
typedef CHAR16* EFI_STRING;
typedef UINT16 EFI_IMAGE_ID;
typedef UINT16 EFI_QUESTION_ID;
typedef UINT16 EFI_STRING_ID;
typedef UINT16 EFI_FORM_ID;
typedef UINT16 EFI_VARSTORE_ID;
typedef UINT16 EFI_ANIMATION_ID;

typedef UINT16 EFI_DEFAULT_ID;

typedef UINT32 EFI_HII_FONT_STYLE;

#pragma pack(1)
typedef struct {
EFI_GUID PackageListGuid;
UINT32 PackageLength;
} EFI_HII_PACKAGE_LIST_HEADER;

typedef struct {
UINT32 Length:24;
UINT32 Type:8;

} EFI_HII_PACKAGE_HEADER;
typedef struct {

CHAR16 UnicodeWeight;

UINT8 Attributes;

UINT8 GlyphCol1[19];
} EFI_NARROW_GLYPH;

typedef struct {

CHAR16 UnicodeWeight;

UINT8 Attributes;

UINT8 GlyphCol1[19];

UINT8 GlyphCol2[19];

UINT8 Pad[3];
} EFI_WIDE_GLYPH;

typedef struct _EFI_HII_SIMPLE_FONT_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;
UINT16 NumberOfNarrowGlyphs;
UINT16 NumberOfWideGlyphs;

} EFI_HII_SIMPLE_FONT_PACKAGE_HDR;
typedef struct _EFI_HII_GLYPH_INFO {
UINT16 Width;
UINT16 Height;
INT16 OffsetX;
INT16 OffsetY;
INT16 AdvanceX;
} EFI_HII_GLYPH_INFO;

typedef struct _EFI_HII_FONT_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;
UINT32 HdrSize;
UINT32 GlyphBlockOffset;
EFI_HII_GLYPH_INFO Cell;
EFI_HII_FONT_STYLE FontStyle;
CHAR16 FontFamily[1];
} EFI_HII_FONT_PACKAGE_HDR;
typedef struct _EFI_HII_GLYPH_BLOCK {
UINT8 BlockType;
} EFI_HII_GLYPH_BLOCK;

typedef struct _EFI_HII_GIBT_DEFAULTS_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
EFI_HII_GLYPH_INFO Cell;
} EFI_HII_GIBT_DEFAULTS_BLOCK;

typedef struct _EFI_HII_GIBT_DUPLICATE_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
CHAR16 CharValue;
} EFI_HII_GIBT_DUPLICATE_BLOCK;

typedef struct _EFI_GLYPH_GIBT_END_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
} EFI_GLYPH_GIBT_END_BLOCK;

typedef struct _EFI_HII_GIBT_EXT1_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT8 BlockType2;
UINT8 Length;
} EFI_HII_GIBT_EXT1_BLOCK;

typedef struct _EFI_HII_GIBT_EXT2_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT8 BlockType2;
UINT16 Length;
} EFI_HII_GIBT_EXT2_BLOCK;

typedef struct _EFI_HII_GIBT_EXT4_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT8 BlockType2;
UINT32 Length;
} EFI_HII_GIBT_EXT4_BLOCK;

typedef struct _EFI_HII_GIBT_GLYPH_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
EFI_HII_GLYPH_INFO Cell;
UINT8 BitmapData[1];
} EFI_HII_GIBT_GLYPH_BLOCK;

typedef struct _EFI_HII_GIBT_GLYPHS_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
EFI_HII_GLYPH_INFO Cell;
UINT16 Count;
UINT8 BitmapData[1];
} EFI_HII_GIBT_GLYPHS_BLOCK;

typedef struct _EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT8 BitmapData[1];
} EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK;

typedef struct _EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT16 Count;
UINT8 BitmapData[1];
} EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK;

typedef struct _EFI_HII_GIBT_SKIP1_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT8 SkipCount;
} EFI_HII_GIBT_SKIP1_BLOCK;

typedef struct _EFI_HII_GIBT_SKIP2_BLOCK {
EFI_HII_GLYPH_BLOCK Header;
UINT16 SkipCount;
} EFI_HII_GIBT_SKIP2_BLOCK;
typedef struct _EFI_HII_DEVICE_PATH_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;

} EFI_HII_DEVICE_PATH_PACKAGE_HDR;
typedef struct _EFI_HII_GUID_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;
EFI_GUID Guid;

} EFI_HII_GUID_PACKAGE_HDR;
typedef struct _EFI_HII_STRING_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;
UINT32 HdrSize;
UINT32 StringInfoOffset;
CHAR16 LanguageWindow[16];
EFI_STRING_ID LanguageName;
CHAR8 Language[1];
} EFI_HII_STRING_PACKAGE_HDR;

typedef struct {
UINT8 BlockType;
} EFI_HII_STRING_BLOCK;
typedef struct _EFI_HII_SIBT_DUPLICATE_BLOCK {
EFI_HII_STRING_BLOCK Header;
EFI_STRING_ID StringId;
} EFI_HII_SIBT_DUPLICATE_BLOCK;

typedef struct _EFI_HII_SIBT_END_BLOCK {
EFI_HII_STRING_BLOCK Header;
} EFI_HII_SIBT_END_BLOCK;

typedef struct _EFI_HII_SIBT_EXT1_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 BlockType2;
UINT8 Length;
} EFI_HII_SIBT_EXT1_BLOCK;

typedef struct _EFI_HII_SIBT_EXT2_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 BlockType2;
UINT16 Length;
} EFI_HII_SIBT_EXT2_BLOCK;

typedef struct _EFI_HII_SIBT_EXT4_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 BlockType2;
UINT32 Length;
} EFI_HII_SIBT_EXT4_BLOCK;

typedef struct _EFI_HII_SIBT_FONT_BLOCK {
EFI_HII_SIBT_EXT2_BLOCK Header;
UINT8 FontId;
UINT16 FontSize;
EFI_HII_FONT_STYLE FontStyle;
CHAR16 FontName[1];
} EFI_HII_SIBT_FONT_BLOCK;

typedef struct _EFI_HII_SIBT_SKIP1_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 SkipCount;
} EFI_HII_SIBT_SKIP1_BLOCK;

typedef struct _EFI_HII_SIBT_SKIP2_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT16 SkipCount;
} EFI_HII_SIBT_SKIP2_BLOCK;

typedef struct _EFI_HII_SIBT_STRING_SCSU_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 StringText[1];
} EFI_HII_SIBT_STRING_SCSU_BLOCK;

typedef struct _EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 FontIdentifier;
UINT8 StringText[1];
} EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK;

typedef struct _EFI_HII_SIBT_STRINGS_SCSU_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT16 StringCount;
UINT8 StringText[1];
} EFI_HII_SIBT_STRINGS_SCSU_BLOCK;

typedef struct _EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 FontIdentifier;
UINT16 StringCount;
UINT8 StringText[1];
} EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK;

typedef struct _EFI_HII_SIBT_STRING_UCS2_BLOCK {
EFI_HII_STRING_BLOCK Header;
CHAR16 StringText[1];
} EFI_HII_SIBT_STRING_UCS2_BLOCK;

typedef struct _EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 FontIdentifier;
CHAR16 StringText[1];
} EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK;

typedef struct _EFI_HII_SIBT_STRINGS_UCS2_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT16 StringCount;
CHAR16 StringText[1];
} EFI_HII_SIBT_STRINGS_UCS2_BLOCK;

typedef struct _EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK {
EFI_HII_STRING_BLOCK Header;
UINT8 FontIdentifier;
UINT16 StringCount;
CHAR16 StringText[1];
} EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK;

typedef struct _EFI_HII_IMAGE_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;
UINT32 ImageInfoOffset;
UINT32 PaletteInfoOffset;
} EFI_HII_IMAGE_PACKAGE_HDR;

typedef struct _EFI_HII_IMAGE_BLOCK {
UINT8 BlockType;
} EFI_HII_IMAGE_BLOCK;
typedef struct _EFI_HII_IIBT_END_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
} EFI_HII_IIBT_END_BLOCK;

typedef struct _EFI_HII_IIBT_EXT1_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 BlockType2;
UINT8 Length;
} EFI_HII_IIBT_EXT1_BLOCK;

typedef struct _EFI_HII_IIBT_EXT2_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 BlockType2;
UINT16 Length;
} EFI_HII_IIBT_EXT2_BLOCK;

typedef struct _EFI_HII_IIBT_EXT4_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 BlockType2;
UINT32 Length;
} EFI_HII_IIBT_EXT4_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_1BIT_BASE {
UINT16 Width;
UINT16 Height;
UINT8 Data[1];
} EFI_HII_IIBT_IMAGE_1BIT_BASE;

typedef struct _EFI_HII_IIBT_IMAGE_1BIT_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_1BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_1BIT_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_1BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK;

typedef struct _EFI_HII_RGB_PIXEL {
UINT8 b;
UINT8 g;
UINT8 r;
} EFI_HII_RGB_PIXEL;

typedef struct _EFI_HII_IIBT_IMAGE_24BIT_BASE {
UINT16 Width;
UINT16 Height;
EFI_HII_RGB_PIXEL Bitmap[1];
} EFI_HII_IIBT_IMAGE_24BIT_BASE;

typedef struct _EFI_HII_IIBT_IMAGE_24BIT_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
EFI_HII_IIBT_IMAGE_24BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_24BIT_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
EFI_HII_IIBT_IMAGE_24BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_4BIT_BASE {
UINT16 Width;
UINT16 Height;
UINT8 Data[1];
} EFI_HII_IIBT_IMAGE_4BIT_BASE;

typedef struct _EFI_HII_IIBT_IMAGE_4BIT_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_4BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_4BIT_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_4BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_8BIT_BASE {
UINT16 Width;
UINT16 Height;
UINT8 Data[1];
} EFI_HII_IIBT_IMAGE_8BIT_BASE;

typedef struct _EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_8BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_8BIT_BLOCK;

typedef struct _EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 PaletteIndex;
EFI_HII_IIBT_IMAGE_8BIT_BASE Bitmap;
} EFI_HII_IIBT_IMAGE_8BIT_TRAN_BLOCK;

typedef struct _EFI_HII_IIBT_DUPLICATE_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
EFI_IMAGE_ID ImageId;
} EFI_HII_IIBT_DUPLICATE_BLOCK;

typedef struct _EFI_HII_IIBT_JPEG_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT32 Size;
UINT8 Data[1];
} EFI_HII_IIBT_JPEG_BLOCK;

typedef struct _EFI_HII_IIBT_SKIP1_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT8 SkipCount;
} EFI_HII_IIBT_SKIP1_BLOCK;

typedef struct _EFI_HII_IIBT_SKIP2_BLOCK {
EFI_HII_IMAGE_BLOCK Header;
UINT16 SkipCount;
} EFI_HII_IIBT_SKIP2_BLOCK;

typedef struct _EFI_HII_IMAGE_PALETTE_INFO_HEADER {
UINT16 PaletteCount;
} EFI_HII_IMAGE_PALETTE_INFO_HEADER;

typedef struct _EFI_HII_IMAGE_PALETTE_INFO {
UINT16 PaletteSize;
EFI_HII_RGB_PIXEL PaletteValue[1];
} EFI_HII_IMAGE_PALETTE_INFO;
typedef struct _EFI_HII_FORM_PACKAGE_HDR {
EFI_HII_PACKAGE_HEADER Header;

} EFI_HII_FORM_PACKAGE_HDR;

typedef struct {
UINT8 Hour;
UINT8 Minute;
UINT8 Second;
} EFI_HII_TIME;

typedef struct {
UINT16 Year;
UINT8 Month;
UINT8 Day;
} EFI_HII_DATE;

typedef struct {
EFI_QUESTION_ID QuestionId;
EFI_FORM_ID FormId;
EFI_GUID FormSetGuid;
EFI_STRING_ID DevicePath;
} EFI_HII_REF;

typedef union {
UINT8 u8;
UINT16 u16;
UINT32 u32;
UINT64 u64;
BOOLEAN b;
EFI_HII_TIME time;
EFI_HII_DATE date;
EFI_STRING_ID string;
EFI_HII_REF ref;

} EFI_IFR_TYPE_VALUE;
typedef struct _EFI_IFR_OP_HEADER {
UINT8 OpCode;
UINT8 Length:7;
UINT8 Scope:1;
} EFI_IFR_OP_HEADER;

typedef struct _EFI_IFR_STATEMENT_HEADER {
EFI_STRING_ID Prompt;
EFI_STRING_ID Help;
} EFI_IFR_STATEMENT_HEADER;

typedef struct _EFI_IFR_QUESTION_HEADER {
EFI_IFR_STATEMENT_HEADER Header;
EFI_QUESTION_ID QuestionId;
EFI_VARSTORE_ID VarStoreId;
union {
EFI_STRING_ID VarName;
UINT16 VarOffset;
} VarStoreInfo;
UINT8 Flags;
} EFI_IFR_QUESTION_HEADER;
typedef struct _EFI_IFR_DEFAULTSTORE {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID DefaultName;
UINT16 DefaultId;
} EFI_IFR_DEFAULTSTORE;
typedef struct _EFI_IFR_VARSTORE {
EFI_IFR_OP_HEADER Header;
EFI_GUID Guid;
EFI_VARSTORE_ID VarStoreId;
UINT16 Size;
UINT8 Name[1];
} EFI_IFR_VARSTORE;

typedef struct _EFI_IFR_VARSTORE_EFI {
EFI_IFR_OP_HEADER Header;
EFI_VARSTORE_ID VarStoreId;
EFI_GUID Guid;
UINT32 Attributes;
UINT16 Size;
UINT8 Name[1];
} EFI_IFR_VARSTORE_EFI;

typedef struct _EFI_IFR_VARSTORE_NAME_VALUE {
EFI_IFR_OP_HEADER Header;
EFI_VARSTORE_ID VarStoreId;
EFI_GUID Guid;
} EFI_IFR_VARSTORE_NAME_VALUE;

typedef struct _EFI_IFR_FORM_SET {
EFI_IFR_OP_HEADER Header;
EFI_GUID Guid;
EFI_STRING_ID FormSetTitle;
EFI_STRING_ID Help;
UINT8 Flags;

} EFI_IFR_FORM_SET;

typedef struct _EFI_IFR_END {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_END;

typedef struct _EFI_IFR_FORM {
EFI_IFR_OP_HEADER Header;
UINT16 FormId;
EFI_STRING_ID FormTitle;
} EFI_IFR_FORM;

typedef struct _EFI_IFR_IMAGE {
EFI_IFR_OP_HEADER Header;
EFI_IMAGE_ID Id;
} EFI_IFR_IMAGE;

typedef struct _EFI_IFR_MODAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MODAL;

typedef struct _EFI_IFR_LOCKED {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_LOCKED;

typedef struct _EFI_IFR_RULE {
EFI_IFR_OP_HEADER Header;
UINT8 RuleId;
} EFI_IFR_RULE;

typedef struct _EFI_IFR_DEFAULT {
EFI_IFR_OP_HEADER Header;
UINT16 DefaultId;
UINT8 Type;
EFI_IFR_TYPE_VALUE Value;
} EFI_IFR_DEFAULT;

typedef struct _EFI_IFR_VALUE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_VALUE;

typedef struct _EFI_IFR_SUBTITLE {
EFI_IFR_OP_HEADER Header;
EFI_IFR_STATEMENT_HEADER Statement;
UINT8 Flags;
} EFI_IFR_SUBTITLE;

typedef struct _EFI_IFR_CHECKBOX {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 Flags;
} EFI_IFR_CHECKBOX;

typedef struct _EFI_IFR_TEXT {
EFI_IFR_OP_HEADER Header;
EFI_IFR_STATEMENT_HEADER Statement;
EFI_STRING_ID TextTwo;
} EFI_IFR_TEXT;

typedef struct _EFI_IFR_REF {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
EFI_FORM_ID FormId;
} EFI_IFR_REF;

typedef struct _EFI_IFR_REF2 {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
EFI_FORM_ID FormId;
EFI_QUESTION_ID QuestionId;
} EFI_IFR_REF2;

typedef struct _EFI_IFR_REF3 {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
EFI_FORM_ID FormId;
EFI_QUESTION_ID QuestionId;
EFI_GUID FormSetId;
} EFI_IFR_REF3;

typedef struct _EFI_IFR_REF4 {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
EFI_FORM_ID FormId;
EFI_QUESTION_ID QuestionId;
EFI_GUID FormSetId;
EFI_STRING_ID DevicePath;
} EFI_IFR_REF4;

typedef struct _EFI_IFR_REF5 {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
} EFI_IFR_REF5;

typedef struct _EFI_IFR_RESET_BUTTON {
EFI_IFR_OP_HEADER Header;
EFI_IFR_STATEMENT_HEADER Statement;
EFI_DEFAULT_ID DefaultId;
} EFI_IFR_RESET_BUTTON;

typedef struct _EFI_IFR_ACTION {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
EFI_STRING_ID QuestionConfig;
} EFI_IFR_ACTION;

typedef struct _EFI_IFR_ACTION_1 {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
} EFI_IFR_ACTION_1;

typedef struct _EFI_IFR_DATE {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 Flags;
} EFI_IFR_DATE;
typedef union {
struct {
UINT8 MinValue;
UINT8 MaxValue;
UINT8 Step;
} u8;
struct {
UINT16 MinValue;
UINT16 MaxValue;
UINT16 Step;
} u16;
struct {
UINT32 MinValue;
UINT32 MaxValue;
UINT32 Step;
} u32;
struct {
UINT64 MinValue;
UINT64 MaxValue;
UINT64 Step;
} u64;
} MINMAXSTEP_DATA;

typedef struct _EFI_IFR_NUMERIC {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 Flags;
MINMAXSTEP_DATA data;
} EFI_IFR_NUMERIC;
typedef struct _EFI_IFR_ONE_OF {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 Flags;
MINMAXSTEP_DATA data;
} EFI_IFR_ONE_OF;

typedef struct _EFI_IFR_STRING {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 MinSize;
UINT8 MaxSize;
UINT8 Flags;
} EFI_IFR_STRING;

typedef struct _EFI_IFR_PASSWORD {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT16 MinSize;
UINT16 MaxSize;
} EFI_IFR_PASSWORD;

typedef struct _EFI_IFR_ORDERED_LIST {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 MaxContainers;
UINT8 Flags;
} EFI_IFR_ORDERED_LIST;

typedef struct _EFI_IFR_TIME {
EFI_IFR_OP_HEADER Header;
EFI_IFR_QUESTION_HEADER Question;
UINT8 Flags;
} EFI_IFR_TIME;
typedef struct _EFI_IFR_DISABLE_IF {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_DISABLE_IF;

typedef struct _EFI_IFR_SUPPRESS_IF {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_SUPPRESS_IF;

typedef struct _EFI_IFR_GRAY_OUT_IF {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_GRAY_OUT_IF;

typedef struct _EFI_IFR_INCONSISTENT_IF {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID Error;
} EFI_IFR_INCONSISTENT_IF;

typedef struct _EFI_IFR_NO_SUBMIT_IF {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID Error;
} EFI_IFR_NO_SUBMIT_IF;

typedef struct _EFI_IFR_REFRESH {
EFI_IFR_OP_HEADER Header;
UINT8 RefreshInterval;
} EFI_IFR_REFRESH;

typedef struct _EFI_IFR_VARSTORE_DEVICE {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID DevicePath;
} EFI_IFR_VARSTORE_DEVICE;

typedef struct _EFI_IFR_ONE_OF_OPTION {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID Option;
UINT8 Flags;
UINT8 Type;
EFI_IFR_TYPE_VALUE Value;
} EFI_IFR_ONE_OF_OPTION;
typedef struct _EFI_IFR_GUID {
EFI_IFR_OP_HEADER Header;
EFI_GUID Guid;

} EFI_IFR_GUID;

typedef struct _EFI_IFR_REFRESH_ID {
EFI_IFR_OP_HEADER Header;
EFI_GUID RefreshEventGroupId;
} EFI_IFR_REFRESH_ID;

typedef struct _EFI_IFR_DUP {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_DUP;

typedef struct _EFI_IFR_EQ_ID_ID {
EFI_IFR_OP_HEADER Header;
EFI_QUESTION_ID QuestionId1;
EFI_QUESTION_ID QuestionId2;
} EFI_IFR_EQ_ID_ID;

typedef struct _EFI_IFR_EQ_ID_VAL {
EFI_IFR_OP_HEADER Header;
EFI_QUESTION_ID QuestionId;
UINT16 Value;
} EFI_IFR_EQ_ID_VAL;

typedef struct _EFI_IFR_EQ_ID_VAL_LIST {
EFI_IFR_OP_HEADER Header;
EFI_QUESTION_ID QuestionId;
UINT16 ListLength;
UINT16 ValueList[1];
} EFI_IFR_EQ_ID_VAL_LIST;

typedef struct _EFI_IFR_UINT8 {
EFI_IFR_OP_HEADER Header;
UINT8 Value;
} EFI_IFR_UINT8;

typedef struct _EFI_IFR_UINT16 {
EFI_IFR_OP_HEADER Header;
UINT16 Value;
} EFI_IFR_UINT16;

typedef struct _EFI_IFR_UINT32 {
EFI_IFR_OP_HEADER Header;
UINT32 Value;
} EFI_IFR_UINT32;

typedef struct _EFI_IFR_UINT64 {
EFI_IFR_OP_HEADER Header;
UINT64 Value;
} EFI_IFR_UINT64;

typedef struct _EFI_IFR_QUESTION_REF1 {
EFI_IFR_OP_HEADER Header;
EFI_QUESTION_ID QuestionId;
} EFI_IFR_QUESTION_REF1;

typedef struct _EFI_IFR_QUESTION_REF2 {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_QUESTION_REF2;

typedef struct _EFI_IFR_QUESTION_REF3 {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_QUESTION_REF3;

typedef struct _EFI_IFR_QUESTION_REF3_2 {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID DevicePath;
} EFI_IFR_QUESTION_REF3_2;

typedef struct _EFI_IFR_QUESTION_REF3_3 {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID DevicePath;
EFI_GUID Guid;
} EFI_IFR_QUESTION_REF3_3;

typedef struct _EFI_IFR_RULE_REF {
EFI_IFR_OP_HEADER Header;
UINT8 RuleId;
} EFI_IFR_RULE_REF;

typedef struct _EFI_IFR_STRING_REF1 {
EFI_IFR_OP_HEADER Header;
EFI_STRING_ID StringId;
} EFI_IFR_STRING_REF1;

typedef struct _EFI_IFR_STRING_REF2 {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_STRING_REF2;

typedef struct _EFI_IFR_THIS {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_THIS;

typedef struct _EFI_IFR_TRUE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TRUE;

typedef struct _EFI_IFR_FALSE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_FALSE;

typedef struct _EFI_IFR_ONE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_ONE;

typedef struct _EFI_IFR_ONES {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_ONES;

typedef struct _EFI_IFR_ZERO {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_ZERO;

typedef struct _EFI_IFR_UNDEFINED {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_UNDEFINED;

typedef struct _EFI_IFR_VERSION {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_VERSION;

typedef struct _EFI_IFR_LENGTH {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_LENGTH;

typedef struct _EFI_IFR_NOT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_NOT;

typedef struct _EFI_IFR_BITWISE_NOT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_BITWISE_NOT;

typedef struct _EFI_IFR_TO_BOOLEAN {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TO_BOOLEAN;
typedef struct _EFI_IFR_TO_STRING {
EFI_IFR_OP_HEADER Header;
UINT8 Format;
} EFI_IFR_TO_STRING;

typedef struct _EFI_IFR_TO_UINT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TO_UINT;

typedef struct _EFI_IFR_TO_UPPER {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TO_UPPER;

typedef struct _EFI_IFR_TO_LOWER {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TO_LOWER;

typedef struct _EFI_IFR_ADD {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_ADD;

typedef struct _EFI_IFR_AND {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_AND;

typedef struct _EFI_IFR_BITWISE_AND {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_BITWISE_AND;

typedef struct _EFI_IFR_BITWISE_OR {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_BITWISE_OR;

typedef struct _EFI_IFR_CATENATE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_CATENATE;

typedef struct _EFI_IFR_DIVIDE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_DIVIDE;

typedef struct _EFI_IFR_EQUAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_EQUAL;

typedef struct _EFI_IFR_GREATER_EQUAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_GREATER_EQUAL;

typedef struct _EFI_IFR_GREATER_THAN {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_GREATER_THAN;

typedef struct _EFI_IFR_LESS_EQUAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_LESS_EQUAL;

typedef struct _EFI_IFR_LESS_THAN {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_LESS_THAN;

typedef struct _EFI_IFR_MATCH {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MATCH;

typedef struct _EFI_IFR_MULTIPLY {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MULTIPLY;

typedef struct _EFI_IFR_MODULO {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MODULO;

typedef struct _EFI_IFR_NOT_EQUAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_NOT_EQUAL;

typedef struct _EFI_IFR_OR {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_OR;

typedef struct _EFI_IFR_SHIFT_LEFT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_SHIFT_LEFT;

typedef struct _EFI_IFR_SHIFT_RIGHT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_SHIFT_RIGHT;

typedef struct _EFI_IFR_SUBTRACT {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_SUBTRACT;

typedef struct _EFI_IFR_CONDITIONAL {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_CONDITIONAL;

typedef struct _EFI_IFR_FIND {
EFI_IFR_OP_HEADER Header;
UINT8 Format;
} EFI_IFR_FIND;

typedef struct _EFI_IFR_MID {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MID;

typedef struct _EFI_IFR_TOKEN {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_TOKEN;
typedef struct _EFI_IFR_SPAN {
EFI_IFR_OP_HEADER Header;
UINT8 Flags;
} EFI_IFR_SPAN;

typedef struct _EFI_IFR_SECURITY {

EFI_IFR_OP_HEADER Header;

EFI_GUID Permissions;
} EFI_IFR_SECURITY;

typedef struct _EFI_IFR_FORM_MAP_METHOD {

EFI_STRING_ID MethodTitle;

EFI_GUID MethodIdentifier;
} EFI_IFR_FORM_MAP_METHOD;

typedef struct _EFI_IFR_FORM_MAP {

EFI_IFR_OP_HEADER Header;

EFI_FORM_ID FormId;

} EFI_IFR_FORM_MAP;

typedef struct _EFI_IFR_SET {

EFI_IFR_OP_HEADER Header;

EFI_VARSTORE_ID VarStoreId;
union {

EFI_STRING_ID VarName;

UINT16 VarOffset;
} VarStoreInfo;

UINT8 VarStoreType;
} EFI_IFR_SET;

typedef struct _EFI_IFR_GET {

EFI_IFR_OP_HEADER Header;

EFI_VARSTORE_ID VarStoreId;
union {

EFI_STRING_ID VarName;

UINT16 VarOffset;
} VarStoreInfo;

UINT8 VarStoreType;
} EFI_IFR_GET;

typedef struct _EFI_IFR_READ {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_READ;

typedef struct _EFI_IFR_WRITE {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_WRITE;

typedef struct _EFI_IFR_MAP {
EFI_IFR_OP_HEADER Header;
} EFI_IFR_MAP;
typedef enum {
EfiKeyLCtrl,
EfiKeyA0,
EfiKeyLAlt,
EfiKeySpaceBar,
EfiKeyA2,
EfiKeyA3,
EfiKeyA4,
EfiKeyRCtrl,
EfiKeyLeftArrow,
EfiKeyDownArrow,
EfiKeyRightArrow,
EfiKeyZero,
EfiKeyPeriod,
EfiKeyEnter,
EfiKeyLShift,
EfiKeyB0,
EfiKeyB1,
EfiKeyB2,
EfiKeyB3,
EfiKeyB4,
EfiKeyB5,
EfiKeyB6,
EfiKeyB7,
EfiKeyB8,
EfiKeyB9,
EfiKeyB10,
EfiKeyRShift,
EfiKeyUpArrow,
EfiKeyOne,
EfiKeyTwo,
EfiKeyThree,
EfiKeyCapsLock,
EfiKeyC1,
EfiKeyC2,
EfiKeyC3,
EfiKeyC4,
EfiKeyC5,
EfiKeyC6,
EfiKeyC7,
EfiKeyC8,
EfiKeyC9,
EfiKeyC10,
EfiKeyC11,
EfiKeyC12,
EfiKeyFour,
EfiKeyFive,
EfiKeySix,
EfiKeyPlus,
EfiKeyTab,
EfiKeyD1,
EfiKeyD2,
EfiKeyD3,
EfiKeyD4,
EfiKeyD5,
EfiKeyD6,
EfiKeyD7,
EfiKeyD8,
EfiKeyD9,
EfiKeyD10,
EfiKeyD11,
EfiKeyD12,
EfiKeyD13,
EfiKeyDel,
EfiKeyEnd,
EfiKeyPgDn,
EfiKeySeven,
EfiKeyEight,
EfiKeyNine,
EfiKeyE0,
EfiKeyE1,
EfiKeyE2,
EfiKeyE3,
EfiKeyE4,
EfiKeyE5,
EfiKeyE6,
EfiKeyE7,
EfiKeyE8,
EfiKeyE9,
EfiKeyE10,
EfiKeyE11,
EfiKeyE12,
EfiKeyBackSpace,
EfiKeyIns,
EfiKeyHome,
EfiKeyPgUp,
EfiKeyNLck,
EfiKeySlash,
EfiKeyAsterisk,
EfiKeyMinus,
EfiKeyEsc,
EfiKeyF1,
EfiKeyF2,
EfiKeyF3,
EfiKeyF4,
EfiKeyF5,
EfiKeyF6,
EfiKeyF7,
EfiKeyF8,
EfiKeyF9,
EfiKeyF10,
EfiKeyF11,
EfiKeyF12,
EfiKeyPrint,
EfiKeySLck,
EfiKeyPause
} EFI_KEY;

typedef struct {

EFI_KEY Key;

CHAR16 Unicode;

CHAR16 ShiftedUnicode;

CHAR16 AltGrUnicode;

CHAR16 ShiftedAltGrUnicode;

UINT16 Modifier;
UINT16 AffectedAttribute;
} EFI_KEY_DESCRIPTOR;
typedef struct {
UINT16 LayoutLength;
EFI_GUID Guid;
UINT32 LayoutDescriptorStringOffset;
UINT8 DescriptorCount;

} EFI_HII_KEYBOARD_LAYOUT;

typedef struct {
EFI_HII_PACKAGE_HEADER Header;
UINT16 LayoutCount;

} EFI_HII_KEYBOARD_PACKAGE_HDR;
typedef struct _EFI_IFR_ANIMATION {

EFI_IFR_OP_HEADER Header;

EFI_ANIMATION_ID Id;
} EFI_IFR_ANIMATION;

typedef struct _EFI_HII_ANIMATION_PACKAGE_HDR {

EFI_HII_PACKAGE_HEADER Header;

UINT32 AnimationInfoOffset;
} EFI_HII_ANIMATION_PACKAGE_HDR;

typedef struct _EFI_HII_ANIMATION_BLOCK {
UINT8 BlockType;

} EFI_HII_ANIMATION_BLOCK;
typedef struct _EFI_HII_AIBT_EXT1_BLOCK {

EFI_HII_ANIMATION_BLOCK Header;

UINT8 BlockType2;

UINT8 Length;
} EFI_HII_AIBT_EXT1_BLOCK;

typedef struct _EFI_HII_AIBT_EXT2_BLOCK {

EFI_HII_ANIMATION_BLOCK Header;

UINT8 BlockType2;

UINT16 Length;
} EFI_HII_AIBT_EXT2_BLOCK;

typedef struct _EFI_HII_AIBT_EXT4_BLOCK {

EFI_HII_ANIMATION_BLOCK Header;

UINT8 BlockType2;

UINT32 Length;
} EFI_HII_AIBT_EXT4_BLOCK;

typedef struct _EFI_HII_ANIMATION_CELL {

UINT16 OffsetX;

UINT16 OffsetY;

EFI_IMAGE_ID ImageId;

UINT16 Delay;
} EFI_HII_ANIMATION_CELL;

typedef struct _EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK {
EFI_IMAGE_ID DftImageId;

UINT16 Width;

UINT16 Height;

UINT16 CellCount;

EFI_HII_ANIMATION_CELL AnimationCell[1];
} EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK;

typedef struct _EFI_HII_AIBT_CLEAR_IMAGES_BLOCK {
EFI_IMAGE_ID DftImageId;

UINT16 Width;

UINT16 Height;

UINT16 CellCount;

EFI_HII_RGB_PIXEL BackgndColor;

EFI_HII_ANIMATION_CELL AnimationCell[1];
} EFI_HII_AIBT_CLEAR_IMAGES_BLOCK;

typedef struct _EFI_HII_AIBT_RESTORE_SCRN_BLOCK {
EFI_IMAGE_ID DftImageId;

UINT16 Width;

UINT16 Height;

UINT16 CellCount;

EFI_HII_ANIMATION_CELL AnimationCell[1];
} EFI_HII_AIBT_RESTORE_SCRN_BLOCK;

typedef EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK EFI_HII_AIBT_OVERLAY_IMAGES_LOOP_BLOCK;

typedef EFI_HII_AIBT_CLEAR_IMAGES_BLOCK EFI_HII_AIBT_CLEAR_IMAGES_LOOP_BLOCK;

typedef EFI_HII_AIBT_RESTORE_SCRN_BLOCK EFI_HII_AIBT_RESTORE_SCRN_LOOP_BLOCK;

typedef struct _EFI_HII_AIBT_DUPLICATE_BLOCK {

EFI_ANIMATION_ID AnimationId;
} EFI_HII_AIBT_DUPLICATE_BLOCK;

typedef struct _EFI_HII_AIBT_SKIP1_BLOCK {

UINT8 SkipCount;
} EFI_HII_AIBT_SKIP1_BLOCK;

typedef struct _EFI_HII_AIBT_SKIP2_BLOCK {

UINT16 SkipCount;
} EFI_HII_AIBT_SKIP2_BLOCK;

#pragma pack()
UINTN

LibPcdSetSku (
UINTN SkuId
);
UINT8

LibPcdGet8 (
UINTN TokenNumber
);
UINT16

LibPcdGet16 (
UINTN TokenNumber
);
UINT32

LibPcdGet32 (
UINTN TokenNumber
);
UINT64

LibPcdGet64 (
UINTN TokenNumber
);
void *

LibPcdGetPtr (
UINTN TokenNumber
);
BOOLEAN

LibPcdGetBool (
UINTN TokenNumber
);
UINTN

LibPcdGetSize (
UINTN TokenNumber
);
UINT8

LibPcdGetEx8 (
GUID *Guid,
UINTN TokenNumber
);
UINT16

LibPcdGetEx16 (
GUID *Guid,
UINTN TokenNumber
);
UINT32

LibPcdGetEx32 (
GUID *Guid,
UINTN TokenNumber
);
UINT64

LibPcdGetEx64 (
GUID *Guid,
UINTN TokenNumber
);
void *

LibPcdGetExPtr (
GUID *Guid,
UINTN TokenNumber
);
BOOLEAN

LibPcdGetExBool (
GUID *Guid,
UINTN TokenNumber
);
UINTN

LibPcdGetExSize (
GUID *Guid,
UINTN TokenNumber
);
UINT8

LibPcdSet8 (
UINTN TokenNumber,
UINT8 Value
);
UINT16

LibPcdSet16 (
UINTN TokenNumber,
UINT16 Value
);
UINT32

LibPcdSet32 (
UINTN TokenNumber,
UINT32 Value
);
UINT64

LibPcdSet64 (
UINTN TokenNumber,
UINT64 Value
);
void *

LibPcdSetPtr (
UINTN TokenNumber,
UINTN *SizeOfBuffer,
void *Buffer
);
BOOLEAN

LibPcdSetBool (
UINTN TokenNumber,
BOOLEAN Value
);
UINT8

LibPcdSetEx8 (
GUID *Guid,
UINTN TokenNumber,
UINT8 Value
);
UINT16

LibPcdSetEx16 (
GUID *Guid,
UINTN TokenNumber,
UINT16 Value
);
UINT32

LibPcdSetEx32 (
GUID *Guid,
UINTN TokenNumber,
UINT32 Value
);
UINT64

LibPcdSetEx64 (
GUID *Guid,
UINTN TokenNumber,
UINT64 Value
);
void *

LibPcdSetExPtr (
GUID *Guid,
UINTN TokenNumber,
UINTN *SizeOfBuffer,
void *Buffer
);
BOOLEAN

LibPcdSetExBool (
GUID *Guid,
UINTN TokenNumber,
BOOLEAN Value
);
typedef
void
( *PCD_CALLBACK)(
GUID *CallBackGuid,
UINTN CallBackToken,
void *TokenData,
UINTN TokenDataSize
);
void

LibPcdCallbackOnSet (
GUID *Guid,
UINTN TokenNumber,
PCD_CALLBACK NotificationFunction
);
void

LibPcdCancelCallback (
GUID *Guid,
UINTN TokenNumber,
PCD_CALLBACK NotificationFunction
);
UINTN

LibPcdGetNextToken (
GUID *Guid,
UINTN TokenNumber
);
GUID *

LibPcdGetNextTokenSpace (
GUID *TokenSpaceGuid
);
void *

LibPatchPcdSetPtr (
void *PatchVariable,
UINTN MaximumDatumSize,
UINTN *SizeOfBuffer,
void *Buffer
);

extern GUID gEfiCallerIdGuid;

EFI_STATUS

UefiMain (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);

typedef struct _EFI_DRIVER_BINDING_PROTOCOL EFI_DRIVER_BINDING_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DRIVER_BINDING_SUPPORTED)(
EFI_DRIVER_BINDING_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath
);
typedef
EFI_STATUS
( *EFI_DRIVER_BINDING_START)(
EFI_DRIVER_BINDING_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath
);
typedef
EFI_STATUS
( *EFI_DRIVER_BINDING_STOP)(
EFI_DRIVER_BINDING_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
UINTN NumberOfChildren,
EFI_HANDLE *ChildHandleBuffer
);

struct _EFI_DRIVER_BINDING_PROTOCOL {
EFI_DRIVER_BINDING_SUPPORTED Supported;
EFI_DRIVER_BINDING_START Start;
EFI_DRIVER_BINDING_STOP Stop;
UINT32 Version;

EFI_HANDLE ImageHandle;
EFI_HANDLE DriverBindingHandle;
};

extern EFI_GUID gEfiDriverBindingProtocolGuid;

typedef struct _EFI_DRIVER_CONFIGURATION2_PROTOCOL EFI_DRIVER_CONFIGURATION2_PROTOCOL;

typedef enum {

EfiDriverConfigurationActionNone = 0,

EfiDriverConfigurationActionStopController = 1,

EfiDriverConfigurationActionRestartController = 2,

EfiDriverConfigurationActionRestartPlatform = 3,
EfiDriverConfigurationActionMaximum
} EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED;
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION2_SET_OPTIONS)(
EFI_DRIVER_CONFIGURATION2_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
CHAR8 *Language,
EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *ActionRequired
);
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION2_OPTIONS_VALID)(
EFI_DRIVER_CONFIGURATION2_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle
);
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION2_FORCE_DEFAULTS)(
EFI_DRIVER_CONFIGURATION2_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
UINT32 DefaultType,
EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *ActionRequired
);

struct _EFI_DRIVER_CONFIGURATION2_PROTOCOL {
EFI_DRIVER_CONFIGURATION2_SET_OPTIONS SetOptions;
EFI_DRIVER_CONFIGURATION2_OPTIONS_VALID OptionsValid;
EFI_DRIVER_CONFIGURATION2_FORCE_DEFAULTS ForceDefaults;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiDriverConfiguration2ProtocolGuid;
typedef struct _EFI_DRIVER_CONFIGURATION_PROTOCOL EFI_DRIVER_CONFIGURATION_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION_SET_OPTIONS)(
EFI_DRIVER_CONFIGURATION_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
CHAR8 *Language,
EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *ActionRequired
);
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION_OPTIONS_VALID)(
EFI_DRIVER_CONFIGURATION_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle
);
typedef
EFI_STATUS
( *EFI_DRIVER_CONFIGURATION_FORCE_DEFAULTS)(
EFI_DRIVER_CONFIGURATION_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
UINT32 DefaultType,
EFI_DRIVER_CONFIGURATION_ACTION_REQUIRED *ActionRequired
);

struct _EFI_DRIVER_CONFIGURATION_PROTOCOL {
EFI_DRIVER_CONFIGURATION_SET_OPTIONS SetOptions;
EFI_DRIVER_CONFIGURATION_OPTIONS_VALID OptionsValid;
EFI_DRIVER_CONFIGURATION_FORCE_DEFAULTS ForceDefaults;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiDriverConfigurationProtocolGuid;

typedef struct _EFI_COMPONENT_NAME_PROTOCOL EFI_COMPONENT_NAME_PROTOCOL;
typedef
EFI_STATUS
( *EFI_COMPONENT_NAME_GET_DRIVER_NAME)(
EFI_COMPONENT_NAME_PROTOCOL *This,
CHAR8 *Language,
CHAR16 **DriverName
);
typedef
EFI_STATUS
( *EFI_COMPONENT_NAME_GET_CONTROLLER_NAME)(
EFI_COMPONENT_NAME_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
CHAR8 *Language,
CHAR16 **ControllerName
);

struct _EFI_COMPONENT_NAME_PROTOCOL {
EFI_COMPONENT_NAME_GET_DRIVER_NAME GetDriverName;
EFI_COMPONENT_NAME_GET_CONTROLLER_NAME GetControllerName;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiComponentNameProtocolGuid;

typedef struct _EFI_COMPONENT_NAME2_PROTOCOL EFI_COMPONENT_NAME2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_COMPONENT_NAME2_GET_DRIVER_NAME)(
EFI_COMPONENT_NAME2_PROTOCOL *This,
CHAR8 *Language,
CHAR16 **DriverName
);
typedef
EFI_STATUS
( *EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME)(
EFI_COMPONENT_NAME2_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
CHAR8 *Language,
CHAR16 **ControllerName
);

struct _EFI_COMPONENT_NAME2_PROTOCOL {
EFI_COMPONENT_NAME2_GET_DRIVER_NAME GetDriverName;
EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME GetControllerName;
CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiComponentName2ProtocolGuid;

typedef struct _EFI_DRIVER_DIAGNOSTICS_PROTOCOL EFI_DRIVER_DIAGNOSTICS_PROTOCOL;

typedef enum {

EfiDriverDiagnosticTypeStandard = 0,

EfiDriverDiagnosticTypeExtended = 1,

EfiDriverDiagnosticTypeManufacturing= 2,
EfiDriverDiagnosticTypeMaximum
} EFI_DRIVER_DIAGNOSTIC_TYPE;
typedef
EFI_STATUS
( *EFI_DRIVER_DIAGNOSTICS_RUN_DIAGNOSTICS)(
EFI_DRIVER_DIAGNOSTICS_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
EFI_DRIVER_DIAGNOSTIC_TYPE DiagnosticType,
CHAR8 *Language,
EFI_GUID **ErrorType,
UINTN *BufferSize,
CHAR16 **Buffer
);

struct _EFI_DRIVER_DIAGNOSTICS_PROTOCOL {
EFI_DRIVER_DIAGNOSTICS_RUN_DIAGNOSTICS RunDiagnostics;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiDriverDiagnosticsProtocolGuid;

typedef struct _EFI_DRIVER_DIAGNOSTICS2_PROTOCOL EFI_DRIVER_DIAGNOSTICS2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DRIVER_DIAGNOSTICS2_RUN_DIAGNOSTICS)(
EFI_DRIVER_DIAGNOSTICS2_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
EFI_DRIVER_DIAGNOSTIC_TYPE DiagnosticType,
CHAR8 *Language,
EFI_GUID **ErrorType,
UINTN *BufferSize,
CHAR16 **Buffer
);

struct _EFI_DRIVER_DIAGNOSTICS2_PROTOCOL {
EFI_DRIVER_DIAGNOSTICS2_RUN_DIAGNOSTICS RunDiagnostics;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiDriverDiagnostics2ProtocolGuid;

typedef struct _EFI_GRAPHICS_OUTPUT_PROTOCOL EFI_GRAPHICS_OUTPUT_PROTOCOL;

typedef struct {
UINT32 RedMask;
UINT32 GreenMask;
UINT32 BlueMask;
UINT32 ReservedMask;
} EFI_PIXEL_BITMASK;

typedef enum {

PixelRedGreenBlueReserved8BitPerColor,

PixelBlueGreenRedReserved8BitPerColor,

PixelBitMask,

PixelBltOnly,

PixelFormatMax
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct {

UINT32 Version;

UINT32 HorizontalResolution;

UINT32 VerticalResolution;

EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;

EFI_PIXEL_BITMASK PixelInformation;

UINT32 PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;
typedef
EFI_STATUS
( *EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE)(
EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
UINT32 ModeNumber,
UINTN *SizeOfInfo,
EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info
);
typedef
EFI_STATUS
( *EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE)(
EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
UINT32 ModeNumber
);

typedef struct {
UINT8 Blue;
UINT8 Green;
UINT8 Red;
UINT8 Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef union {
EFI_GRAPHICS_OUTPUT_BLT_PIXEL Pixel;
UINT32 Raw;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL_UNION;

typedef enum {

EfiBltVideoFill,
EfiBltVideoToBltBuffer,
EfiBltBufferToVideo,
EfiBltVideoToVideo,

EfiGraphicsOutputBltOperationMax
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;
typedef
EFI_STATUS
( *EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT)(
EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer,
EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation,
UINTN SourceX,
UINTN SourceY,
UINTN DestinationX,
UINTN DestinationY,
UINTN Width,
UINTN Height,
UINTN Delta
);

typedef struct {

UINT32 MaxMode;

UINT32 Mode;

EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;

UINTN SizeOfInfo;

EFI_PHYSICAL_ADDRESS FrameBufferBase;

UINTN FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE QueryMode;
EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE SetMode;
EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT Blt;

EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
};

extern EFI_GUID gEfiGraphicsOutputProtocolGuid;

typedef struct {
UINT64 Rbx;
UINT64 Rsp;
UINT64 Rbp;
UINT64 Rdi;
UINT64 Rsi;
UINT64 R12;
UINT64 R13;
UINT64 R14;
UINT64 R15;
UINT64 Rip;
UINT64 MxCsr;
UINT8 XmmBuffer[160];
} BASE_LIBRARY_JUMP_BUFFER;
CHAR16 *

StrCpy (
CHAR16 *Destination,
CHAR16 *Source
);
CHAR16 *

StrnCpy (
CHAR16 *Destination,
CHAR16 *Source,
UINTN Length
);
UINTN

StrLen (
CHAR16 *String
);
UINTN

StrSize (
CHAR16 *String
);
INTN

StrCmp (
CHAR16 *FirstString,
CHAR16 *SecondString
);
INTN

StrnCmp (
CHAR16 *FirstString,
CHAR16 *SecondString,
UINTN Length
);
CHAR16 *

StrCat (
CHAR16 *Destination,
CHAR16 *Source
);
CHAR16 *

StrnCat (
CHAR16 *Destination,
CHAR16 *Source,
UINTN Length
);
CHAR16 *

StrStr (
CHAR16 *String,
CHAR16 *SearchString
);
UINTN

StrDecimalToUintn (
CHAR16 *String
);
UINT64

StrDecimalToUint64 (
CHAR16 *String
);
UINTN

StrHexToUintn (
CHAR16 *String
);
UINT64

StrHexToUint64 (
CHAR16 *String
);
CHAR8 *

UnicodeStrToAsciiStr (
CHAR16 *Source,
CHAR8 *Destination
);
CHAR8 *

AsciiStrCpy (
CHAR8 *Destination,
CHAR8 *Source
);
CHAR8 *

AsciiStrnCpy (
CHAR8 *Destination,
CHAR8 *Source,
UINTN Length
);
UINTN

AsciiStrLen (
CHAR8 *String
);
UINTN

AsciiStrSize (
CHAR8 *String
);
INTN

AsciiStrCmp (
CHAR8 *FirstString,
CHAR8 *SecondString
);
INTN

AsciiStriCmp (
CHAR8 *FirstString,
CHAR8 *SecondString
);
INTN

AsciiStrnCmp (
CHAR8 *FirstString,
CHAR8 *SecondString,
UINTN Length
);
CHAR8 *

AsciiStrCat (
CHAR8 *Destination,
CHAR8 *Source
);
CHAR8 *

AsciiStrnCat (
CHAR8 *Destination,
CHAR8 *Source,
UINTN Length
);
CHAR8 *

AsciiStrStr (
CHAR8 *String,
CHAR8 *SearchString
);
UINTN

AsciiStrDecimalToUintn (
CHAR8 *String
);
UINT64

AsciiStrDecimalToUint64 (
CHAR8 *String
);
UINTN

AsciiStrHexToUintn (
CHAR8 *String
);
UINT64

AsciiStrHexToUint64 (
CHAR8 *String
);
CHAR16 *

AsciiStrToUnicodeStr (
CHAR8 *Source,
CHAR16 *Destination
);
UINT8

DecimalToBcd8 (
UINT8 Value
);
UINT8

BcdToDecimal8 (
UINT8 Value
);
LIST_ENTRY *

InitializeListHead (
LIST_ENTRY *ListHead
);
LIST_ENTRY *

InsertHeadList (
LIST_ENTRY *ListHead,
LIST_ENTRY *Entry
);
LIST_ENTRY *

InsertTailList (
LIST_ENTRY *ListHead,
LIST_ENTRY *Entry
);
LIST_ENTRY *

GetFirstNode (
LIST_ENTRY *List
);
LIST_ENTRY *

GetNextNode (
LIST_ENTRY *List,
LIST_ENTRY *Node
);
LIST_ENTRY *

GetPreviousNode (
LIST_ENTRY *List,
LIST_ENTRY *Node
);
BOOLEAN

IsListEmpty (
LIST_ENTRY *ListHead
);
BOOLEAN

IsNull (
LIST_ENTRY *List,
LIST_ENTRY *Node
);
BOOLEAN

IsNodeAtEnd (
LIST_ENTRY *List,
LIST_ENTRY *Node
);
LIST_ENTRY *

SwapListEntries (
LIST_ENTRY *FirstEntry,
LIST_ENTRY *SecondEntry
);
LIST_ENTRY *

RemoveEntryList (
LIST_ENTRY *Entry
);
UINT64

LShiftU64 (
UINT64 Operand,
UINTN Count
);
UINT64

RShiftU64 (
UINT64 Operand,
UINTN Count
);
UINT64

ARShiftU64 (
UINT64 Operand,
UINTN Count
);
UINT32

LRotU32 (
UINT32 Operand,
UINTN Count
);
UINT32

RRotU32 (
UINT32 Operand,
UINTN Count
);
UINT64

LRotU64 (
UINT64 Operand,
UINTN Count
);
UINT64

RRotU64 (
UINT64 Operand,
UINTN Count
);
INTN

LowBitSet32 (
UINT32 Operand
);
INTN

LowBitSet64 (
UINT64 Operand
);
INTN

HighBitSet32 (
UINT32 Operand
);
INTN

HighBitSet64 (
UINT64 Operand
);
UINT32

GetPowerOfTwo32 (
UINT32 Operand
);
UINT64

GetPowerOfTwo64 (
UINT64 Operand
);
UINT16

SwapBytes16 (
UINT16 Value
);
UINT32

SwapBytes32 (
UINT32 Value
);
UINT64

SwapBytes64 (
UINT64 Value
);
UINT64

MultU64x32 (
UINT64 Multiplicand,
UINT32 Multiplier
);
UINT64

MultU64x64 (
UINT64 Multiplicand,
UINT64 Multiplier
);
INT64

MultS64x64 (
INT64 Multiplicand,
INT64 Multiplier
);
UINT64

DivU64x32 (
UINT64 Dividend,
UINT32 Divisor
);
UINT32

ModU64x32 (
UINT64 Dividend,
UINT32 Divisor
);
UINT64

DivU64x32Remainder (
UINT64 Dividend,
UINT32 Divisor,
UINT32 *Remainder
);
UINT64

DivU64x64Remainder (
UINT64 Dividend,
UINT64 Divisor,
UINT64 *Remainder
);
INT64

DivS64x64Remainder (
INT64 Dividend,
INT64 Divisor,
INT64 *Remainder
);
UINT16

ReadUnaligned16 (
UINT16 *Buffer
);
UINT16

WriteUnaligned16 (
UINT16 *Buffer,
UINT16 Value
);
UINT32

ReadUnaligned24 (
UINT32 *Buffer
);
UINT32

WriteUnaligned24 (
UINT32 *Buffer,
UINT32 Value
);
UINT32

ReadUnaligned32 (
UINT32 *Buffer
);
UINT32

WriteUnaligned32 (
UINT32 *Buffer,
UINT32 Value
);
UINT64

ReadUnaligned64 (
UINT64 *Buffer
);
UINT64

WriteUnaligned64 (
UINT64 *Buffer,
UINT64 Value
);
UINT8

BitFieldRead8 (
UINT8 Operand,
UINTN StartBit,
UINTN EndBit
);
UINT8

BitFieldWrite8 (
UINT8 Operand,
UINTN StartBit,
UINTN EndBit,
UINT8 Value
);
UINT8

BitFieldOr8 (
UINT8 Operand,
UINTN StartBit,
UINTN EndBit,
UINT8 OrData
);
UINT8

BitFieldAnd8 (
UINT8 Operand,
UINTN StartBit,
UINTN EndBit,
UINT8 AndData
);
UINT8

BitFieldAndThenOr8 (
UINT8 Operand,
UINTN StartBit,
UINTN EndBit,
UINT8 AndData,
UINT8 OrData
);
UINT16

BitFieldRead16 (
UINT16 Operand,
UINTN StartBit,
UINTN EndBit
);
UINT16

BitFieldWrite16 (
UINT16 Operand,
UINTN StartBit,
UINTN EndBit,
UINT16 Value
);
UINT16

BitFieldOr16 (
UINT16 Operand,
UINTN StartBit,
UINTN EndBit,
UINT16 OrData
);
UINT16

BitFieldAnd16 (
UINT16 Operand,
UINTN StartBit,
UINTN EndBit,
UINT16 AndData
);
UINT16

BitFieldAndThenOr16 (
UINT16 Operand,
UINTN StartBit,
UINTN EndBit,
UINT16 AndData,
UINT16 OrData
);
UINT32

BitFieldRead32 (
UINT32 Operand,
UINTN StartBit,
UINTN EndBit
);
UINT32

BitFieldWrite32 (
UINT32 Operand,
UINTN StartBit,
UINTN EndBit,
UINT32 Value
);
UINT32

BitFieldOr32 (
UINT32 Operand,
UINTN StartBit,
UINTN EndBit,
UINT32 OrData
);
UINT32

BitFieldAnd32 (
UINT32 Operand,
UINTN StartBit,
UINTN EndBit,
UINT32 AndData
);
UINT32

BitFieldAndThenOr32 (
UINT32 Operand,
UINTN StartBit,
UINTN EndBit,
UINT32 AndData,
UINT32 OrData
);
UINT64

BitFieldRead64 (
UINT64 Operand,
UINTN StartBit,
UINTN EndBit
);
UINT64

BitFieldWrite64 (
UINT64 Operand,
UINTN StartBit,
UINTN EndBit,
UINT64 Value
);
UINT64

BitFieldOr64 (
UINT64 Operand,
UINTN StartBit,
UINTN EndBit,
UINT64 OrData
);
UINT64

BitFieldAnd64 (
UINT64 Operand,
UINTN StartBit,
UINTN EndBit,
UINT64 AndData
);
UINT64

BitFieldAndThenOr64 (
UINT64 Operand,
UINTN StartBit,
UINTN EndBit,
UINT64 AndData,
UINT64 OrData
);
UINT8

CalculateSum8 (
UINT8 *Buffer,
UINTN Length
);
UINT8

CalculateCheckSum8 (
UINT8 *Buffer,
UINTN Length
);
UINT16

CalculateSum16 (
UINT16 *Buffer,
UINTN Length
);
UINT16

CalculateCheckSum16 (
UINT16 *Buffer,
UINTN Length
);
UINT32

CalculateSum32 (
UINT32 *Buffer,
UINTN Length
);
UINT32

CalculateCheckSum32 (
UINT32 *Buffer,
UINTN Length
);
UINT64

CalculateSum64 (
UINT64 *Buffer,
UINTN Length
);
UINT64

CalculateCheckSum64 (
UINT64 *Buffer,
UINTN Length
);
typedef
void
( *SWITCH_STACK_ENTRY_POINT)(
void *Context1,
void *Context2
);
void

MemoryFence (
void
);
UINTN

SetJump (
BASE_LIBRARY_JUMP_BUFFER *JumpBuffer
);
void

LongJump (
BASE_LIBRARY_JUMP_BUFFER *JumpBuffer,
UINTN Value
);

void

EnableInterrupts (
void
);

void

DisableInterrupts (
void
);
BOOLEAN

SaveAndDisableInterrupts (
void
);

void

EnableDisableInterrupts (
void
);
BOOLEAN

GetInterruptState (
void
);
BOOLEAN

SetInterruptState (
BOOLEAN InterruptState
);
void

CpuPause (
void
);
void

SwitchStack (
SWITCH_STACK_ENTRY_POINT EntryPoint,
void *Context1,
void *Context2,
void *NewStack,
...
);
void

CpuBreakpoint (
void
);
void

CpuDeadLoop (
void
);
typedef union {
struct {
UINT32 CF:1;
UINT32 Reserved_0:1;
UINT32 PF:1;
UINT32 Reserved_1:1;
UINT32 AF:1;
UINT32 Reserved_2:1;
UINT32 ZF:1;
UINT32 SF:1;
UINT32 TF:1;
UINT32 IF:1;
UINT32 DF:1;
UINT32 OF:1;
UINT32 IOPL:2;
UINT32 NT:1;
UINT32 Reserved_3:1;
} Bits;
UINT16 Uint16;
} IA32_FLAGS16;

typedef union {
struct {
UINT32 CF:1;
UINT32 Reserved_0:1;
UINT32 PF:1;
UINT32 Reserved_1:1;
UINT32 AF:1;
UINT32 Reserved_2:1;
UINT32 ZF:1;
UINT32 SF:1;
UINT32 TF:1;
UINT32 IF:1;
UINT32 DF:1;
UINT32 OF:1;
UINT32 IOPL:2;
UINT32 NT:1;
UINT32 Reserved_3:1;
UINT32 RF:1;
UINT32 VM:1;
UINT32 AC:1;
UINT32 VIF:1;
UINT32 VIP:1;
UINT32 ID:1;
UINT32 Reserved_4:10;
} Bits;
UINTN UintN;
} IA32_EFLAGS32;

typedef union {
struct {
UINT32 PE:1;
UINT32 MP:1;
UINT32 EM:1;
UINT32 TS:1;
UINT32 ET:1;
UINT32 NE:1;
UINT32 Reserved_0:10;
UINT32 WP:1;
UINT32 Reserved_1:1;
UINT32 AM:1;
UINT32 Reserved_2:10;
UINT32 NW:1;
UINT32 CD:1;
UINT32 PG:1;
} Bits;
UINTN UintN;
} IA32_CR0;

typedef union {
struct {
UINT32 VME:1;
UINT32 PVI:1;
UINT32 TSD:1;
UINT32 DE:1;
UINT32 PSE:1;
UINT32 PAE:1;
UINT32 MCE:1;
UINT32 PGE:1;
UINT32 PCE:1;

UINT32 OSFXSR:1;

UINT32 OSXMMEXCPT:1;

UINT32 Reserved_0:2;
UINT32 VMXE:1;
UINT32 Reserved_1:18;
} Bits;
UINTN UintN;
} IA32_CR4;

typedef union {
struct {
UINT32 LimitLow:16;
UINT32 BaseLow:16;
UINT32 BaseMid:8;
UINT32 Type:4;
UINT32 S:1;
UINT32 DPL:2;
UINT32 P:1;
UINT32 LimitHigh:4;
UINT32 AVL:1;
UINT32 L:1;
UINT32 DB:1;
UINT32 G:1;
UINT32 BaseHigh:8;
} Bits;
UINT64 Uint64;
} IA32_SEGMENT_DESCRIPTOR;

#pragma pack (1)
typedef struct {
UINT16 Limit;
UINTN Base;
} IA32_DESCRIPTOR;
#pragma pack ()
typedef union {
struct {
UINT32 OffsetLow:16;
UINT32 Selector:16;
UINT32 Reserved_0:8;
UINT32 GateType:8;
UINT32 OffsetHigh:16;
UINT32 OffsetUpper:32;
UINT32 Reserved_1:32;
} Bits;
struct {
UINT64 Uint64;
UINT64 Uint64_1;
} Uint128;
} IA32_IDT_GATE_DESCRIPTOR;

typedef struct {
UINT8 Buffer[512];
} IA32_FX_BUFFER;

typedef struct {
UINT32 Reserved1;
UINT32 Reserved2;
UINT32 Reserved3;
UINT32 Reserved4;
UINT8 BL;
UINT8 BH;
UINT16 Reserved5;
UINT8 DL;
UINT8 DH;
UINT16 Reserved6;
UINT8 CL;
UINT8 CH;
UINT16 Reserved7;
UINT8 AL;
UINT8 AH;
UINT16 Reserved8;
} IA32_BYTE_REGS;

typedef struct {
UINT16 DI;
UINT16 Reserved1;
UINT16 SI;
UINT16 Reserved2;
UINT16 BP;
UINT16 Reserved3;
UINT16 SP;
UINT16 Reserved4;
UINT16 BX;
UINT16 Reserved5;
UINT16 DX;
UINT16 Reserved6;
UINT16 CX;
UINT16 Reserved7;
UINT16 AX;
UINT16 Reserved8;
} IA32_WORD_REGS;

typedef struct {
UINT32 EDI;
UINT32 ESI;
UINT32 EBP;
UINT32 ESP;
UINT32 EBX;
UINT32 EDX;
UINT32 ECX;
UINT32 EAX;
UINT16 DS;
UINT16 ES;
UINT16 FS;
UINT16 GS;
IA32_EFLAGS32 EFLAGS;
UINT32 Eip;
UINT16 CS;
UINT16 SS;
} IA32_DWORD_REGS;

typedef union {
IA32_DWORD_REGS E;
IA32_WORD_REGS X;
IA32_BYTE_REGS H;
} IA32_REGISTER_SET;

typedef struct {
IA32_REGISTER_SET *RealModeState;
void *RealModeBuffer;
UINT32 RealModeBufferSize;
UINT32 ThunkAttributes;
} THUNK_CONTEXT;
UINT32

AsmCpuid (
UINT32 Index,
UINT32 *Eax,
UINT32 *Ebx,
UINT32 *Ecx,
UINT32 *Edx
);
UINT32

AsmCpuidEx (
UINT32 Index,
UINT32 SubIndex,
UINT32 *Eax,
UINT32 *Ebx,
UINT32 *Ecx,
UINT32 *Edx
);
void

AsmDisableCache (
void
);
void

AsmEnableCache (
void
);
UINT32

AsmReadMsr32 (
UINT32 Index
);
UINT32

AsmWriteMsr32 (
UINT32 Index,
UINT32 Value
);
UINT32

AsmMsrOr32 (
UINT32 Index,
UINT32 OrData
);
UINT32

AsmMsrAnd32 (
UINT32 Index,
UINT32 AndData
);
UINT32

AsmMsrAndThenOr32 (
UINT32 Index,
UINT32 AndData,
UINT32 OrData
);
UINT32

AsmMsrBitFieldRead32 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit
);
UINT32

AsmMsrBitFieldWrite32 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT32 Value
);
UINT32

AsmMsrBitFieldOr32 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT32 OrData
);
UINT32

AsmMsrBitFieldAnd32 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT32 AndData
);
UINT32

AsmMsrBitFieldAndThenOr32 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT32 AndData,
UINT32 OrData
);
UINT64

AsmReadMsr64 (
UINT32 Index
);
UINT64

AsmWriteMsr64 (
UINT32 Index,
UINT64 Value
);
UINT64

AsmMsrOr64 (
UINT32 Index,
UINT64 OrData
);
UINT64

AsmMsrAnd64 (
UINT32 Index,
UINT64 AndData
);
UINT64

AsmMsrAndThenOr64 (
UINT32 Index,
UINT64 AndData,
UINT64 OrData
);
UINT64

AsmMsrBitFieldRead64 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit
);
UINT64

AsmMsrBitFieldWrite64 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT64 Value
);
UINT64

AsmMsrBitFieldOr64 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT64 OrData
);
UINT64

AsmMsrBitFieldAnd64 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT64 AndData
);
UINT64

AsmMsrBitFieldAndThenOr64 (
UINT32 Index,
UINTN StartBit,
UINTN EndBit,
UINT64 AndData,
UINT64 OrData
);
UINTN

AsmReadEflags (
void
);
UINTN

AsmReadCr0 (
void
);
UINTN

AsmReadCr2 (
void
);
UINTN

AsmReadCr3 (
void
);
UINTN

AsmReadCr4 (
void
);
UINTN

AsmWriteCr0 (
UINTN Cr0
);
UINTN

AsmWriteCr2 (
UINTN Cr2
);
UINTN

AsmWriteCr3 (
UINTN Cr3
);
UINTN

AsmWriteCr4 (
UINTN Cr4
);
UINTN

AsmReadDr0 (
void
);
UINTN

AsmReadDr1 (
void
);
UINTN

AsmReadDr2 (
void
);
UINTN

AsmReadDr3 (
void
);
UINTN

AsmReadDr4 (
void
);
UINTN

AsmReadDr5 (
void
);
UINTN

AsmReadDr6 (
void
);
UINTN

AsmReadDr7 (
void
);
UINTN

AsmWriteDr0 (
UINTN Dr0
);
UINTN

AsmWriteDr1 (
UINTN Dr1
);
UINTN

AsmWriteDr2 (
UINTN Dr2
);
UINTN

AsmWriteDr3 (
UINTN Dr3
);
UINTN

AsmWriteDr4 (
UINTN Dr4
);
UINTN

AsmWriteDr5 (
UINTN Dr5
);
UINTN

AsmWriteDr6 (
UINTN Dr6
);
UINTN

AsmWriteDr7 (
UINTN Dr7
);
UINT16

AsmReadCs (
void
);
UINT16

AsmReadDs (
void
);
UINT16

AsmReadEs (
void
);
UINT16

AsmReadFs (
void
);
UINT16

AsmReadGs (
void
);
UINT16

AsmReadSs (
void
);
UINT16

AsmReadTr (
void
);
void

AsmReadGdtr (
IA32_DESCRIPTOR *Gdtr
);
void

AsmWriteGdtr (
IA32_DESCRIPTOR *Gdtr
);
void

AsmReadIdtr (
IA32_DESCRIPTOR *Idtr
);
void

AsmWriteIdtr (
IA32_DESCRIPTOR *Idtr
);
UINT16

AsmReadLdtr (
void
);
void

AsmWriteLdtr (
UINT16 Ldtr
);
void

AsmFxSave (
IA32_FX_BUFFER *Buffer
);
void

AsmFxRestore (
IA32_FX_BUFFER *Buffer
);
UINT64

AsmReadMm0 (
void
);
UINT64

AsmReadMm1 (
void
);
UINT64

AsmReadMm2 (
void
);
UINT64

AsmReadMm3 (
void
);
UINT64

AsmReadMm4 (
void
);
UINT64

AsmReadMm5 (
void
);
UINT64

AsmReadMm6 (
void
);
UINT64

AsmReadMm7 (
void
);
void

AsmWriteMm0 (
UINT64 Value
);
void

AsmWriteMm1 (
UINT64 Value
);
void

AsmWriteMm2 (
UINT64 Value
);
void

AsmWriteMm3 (
UINT64 Value
);
void

AsmWriteMm4 (
UINT64 Value
);
void

AsmWriteMm5 (
UINT64 Value
);
void

AsmWriteMm6 (
UINT64 Value
);
void

AsmWriteMm7 (
UINT64 Value
);
UINT64

AsmReadTsc (
void
);
UINT64

AsmReadPmc (
UINT32 Index
);
UINTN

AsmMonitor (
UINTN Eax,
UINTN Ecx,
UINTN Edx
);
UINTN

AsmMwait (
UINTN Eax,
UINTN Ecx
);
void

AsmWbinvd (
void
);
void

AsmInvd (
void
);
void *

AsmFlushCacheLine (
void *LinearAddress
);
void

AsmEnablePaging32 (
SWITCH_STACK_ENTRY_POINT EntryPoint,
void *Context1,
void *Context2,
void *NewStack
);
void

AsmDisablePaging32 (
SWITCH_STACK_ENTRY_POINT EntryPoint,
void *Context1,
void *Context2,
void *NewStack
);
void

AsmEnablePaging64 (
UINT16 Cs,
UINT64 EntryPoint,
UINT64 Context1,
UINT64 Context2,
UINT64 NewStack
);
void

AsmDisablePaging64 (
UINT16 Cs,
UINT32 EntryPoint,
UINT32 Context1,
UINT32 Context2,
UINT32 NewStack
);
void

AsmGetThunk16Properties (
UINT32 *RealModeBufferSize,
UINT32 *ExtraStackSize
);
void

AsmPrepareThunk16 (
THUNK_CONTEXT *ThunkContext
);
void

AsmThunk16 (
THUNK_CONTEXT *ThunkContext
);
void

AsmPrepareAndThunk16 (
THUNK_CONTEXT *ThunkContext
);

typedef struct {
CHAR8 *Language;
CHAR16 *UnicodeString;
} EFI_UNICODE_STRING_TABLE;

typedef enum {
EfiLockUninitialized = 0,
EfiLockReleased = 1,
EfiLockAcquired = 2
} EFI_LOCK_STATE;

typedef struct {
EFI_TPL Tpl;
EFI_TPL OwnerTpl;
EFI_LOCK_STATE Lock;
} EFI_LOCK;
EFI_STATUS

EfiGetSystemConfigurationTable (
EFI_GUID *TableGuid,
void **Table
);
EFI_EVENT

EfiCreateProtocolNotifyEvent(
EFI_GUID *ProtocolGuid,
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction,
void *NotifyContext,
void **Registration
);
EFI_STATUS

EfiNamedEventListen (
EFI_GUID *Name,
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction,
void *NotifyContext,
void *Registration
);
EFI_STATUS

EfiNamedEventSignal (
EFI_GUID *Name
);
EFI_TPL

EfiGetCurrentTpl (
void
);
EFI_LOCK *

EfiInitializeLock (
EFI_LOCK *Lock,
EFI_TPL Priority
);
void

EfiAcquireLock (
EFI_LOCK *Lock
);
EFI_STATUS

EfiAcquireLockOrFail (
EFI_LOCK *Lock
);
void

EfiReleaseLock (
EFI_LOCK *Lock
);
EFI_STATUS

EfiTestManagedDevice (
EFI_HANDLE ControllerHandle,
EFI_HANDLE DriverBindingHandle,
EFI_GUID *ProtocolGuid
);
EFI_STATUS

EfiTestChildHandle (
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle,
EFI_GUID *ProtocolGuid
);
EFI_STATUS

LookupUnicodeString (
CHAR8 *Language,
CHAR8 *SupportedLanguages,
EFI_UNICODE_STRING_TABLE *UnicodeStringTable,
CHAR16 **UnicodeString
);
EFI_STATUS

LookupUnicodeString2 (
CHAR8 *Language,
CHAR8 *SupportedLanguages,
EFI_UNICODE_STRING_TABLE *UnicodeStringTable,
CHAR16 **UnicodeString,
BOOLEAN Iso639Language
);
EFI_STATUS

AddUnicodeString (
CHAR8 *Language,
CHAR8 *SupportedLanguages,
EFI_UNICODE_STRING_TABLE **UnicodeStringTable,
CHAR16 *UnicodeString
);
EFI_STATUS

AddUnicodeString2 (
CHAR8 *Language,
CHAR8 *SupportedLanguages,
EFI_UNICODE_STRING_TABLE **UnicodeStringTable,
CHAR16 *UnicodeString,
BOOLEAN Iso639Language
);
EFI_STATUS

FreeUnicodeStringTable (
EFI_UNICODE_STRING_TABLE *UnicodeStringTable
);
void *

GetVariable (
CHAR16 *Name,
EFI_GUID *Guid
);
void *

GetEfiGlobalVariable (
CHAR16 *Name
);
EFI_STATUS

GetVariable2 (
CHAR16 *Name,
EFI_GUID *Guid,
void **Value,
UINTN *Size
);
EFI_STATUS

GetEfiGlobalVariable2 (
CHAR16 *Name,
void **Value,
UINTN *Size
);
CHAR8 *

GetBestLanguage (
CHAR8 *SupportedLanguages,
BOOLEAN Iso639Language,
...
);
void

CreatePopUp (
UINTN Attribute,
EFI_INPUT_KEY *Key,
...
);
UINTN

GetGlyphWidth (
CHAR16 UnicodeChar
);
UINTN

UnicodeStringDisplayLength (
CHAR16 *String
);
void

EfiSignalEventReadyToBoot (
void
);
void

EfiSignalEventLegacyBoot (
void
);
EFI_STATUS

EfiCreateEventLegacyBoot (
EFI_EVENT *LegacyBootEvent
);
EFI_STATUS

EfiCreateEventLegacyBootEx (
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction,
void *NotifyContext,
EFI_EVENT *LegacyBootEvent
);
EFI_STATUS

EfiCreateEventReadyToBoot (
EFI_EVENT *ReadyToBootEvent
);
EFI_STATUS

EfiCreateEventReadyToBootEx (
EFI_TPL NotifyTpl,
EFI_EVENT_NOTIFY NotifyFunction,
void *NotifyContext,
EFI_EVENT *ReadyToBootEvent
);
void

EfiInitializeFwVolDevicepathNode (
MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *FvDevicePathNode,
EFI_GUID *NameGuid
);
EFI_GUID *

EfiGetNameGuidFromFwVolDevicePathNode (
MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *FvDevicePathNode
);
UINTN

Print (
CHAR16 *Format,
...
);
UINTN

ErrorPrint (
CHAR16 *Format,
...
);
UINTN

AsciiPrint (
CHAR8 *Format,
...
);
UINTN

AsciiErrorPrint (
CHAR8 *Format,
...
);
UINTN

PrintXY (
UINTN PointX,
UINTN PointY,
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *ForeGround,
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BackGround,
CHAR16 *Format,
...
);
UINTN

AsciiPrintXY (
UINTN PointX,
UINTN PointY,
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *ForeGround,
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BackGround,
CHAR8 *Format,
...
);
EFI_STATUS

EfiLibInstallDriverBinding (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable,
EFI_DRIVER_BINDING_PROTOCOL *DriverBinding,
EFI_HANDLE DriverBindingHandle
);
EFI_STATUS

EfiLibInstallAllDriverProtocols (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable,
EFI_DRIVER_BINDING_PROTOCOL *DriverBinding,
EFI_HANDLE DriverBindingHandle,
EFI_COMPONENT_NAME_PROTOCOL *ComponentName,
EFI_DRIVER_CONFIGURATION_PROTOCOL *DriverConfiguration,
EFI_DRIVER_DIAGNOSTICS_PROTOCOL *DriverDiagnostics
);
EFI_STATUS

EfiLibInstallDriverBindingComponentName2 (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable,
EFI_DRIVER_BINDING_PROTOCOL *DriverBinding,
EFI_HANDLE DriverBindingHandle,
EFI_COMPONENT_NAME_PROTOCOL *ComponentName,
EFI_COMPONENT_NAME2_PROTOCOL *ComponentName2
);
EFI_STATUS

EfiLibInstallAllDriverProtocols2 (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable,
EFI_DRIVER_BINDING_PROTOCOL *DriverBinding,
EFI_HANDLE DriverBindingHandle,
EFI_COMPONENT_NAME_PROTOCOL *ComponentName,
EFI_COMPONENT_NAME2_PROTOCOL *ComponentName2,
EFI_DRIVER_CONFIGURATION_PROTOCOL *DriverConfiguration,
EFI_DRIVER_CONFIGURATION2_PROTOCOL *DriverConfiguration2,
EFI_DRIVER_DIAGNOSTICS_PROTOCOL *DriverDiagnostics,
EFI_DRIVER_DIAGNOSTICS2_PROTOCOL *DriverDiagnostics2
);
CHAR16*

CatVSPrint (
CHAR16 *String,
CHAR16 *FormatString,
VA_LIST Marker
);
CHAR16 *

CatSPrint (
CHAR16 *String,
CHAR16 *FormatString,
...
);
extern UINT32 _gUefiDriverRevision;
EFI_STATUS

_ModuleEntryPoint (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
EFI_STATUS

EfiMain (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
void

Exit (
EFI_STATUS Status
);
void

ProcessLibraryConstructorList (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
void

ProcessLibraryDestructorList (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
EFI_STATUS

ProcessModuleEntryPointList (
EFI_HANDLE ImageHandle,
EFI_SYSTEM_TABLE *SystemTable
);
void *

AllocatePages (
UINTN Pages
);
void *

AllocateRuntimePages (
UINTN Pages
);
void *

AllocateReservedPages (
UINTN Pages
);
void

FreePages (
void *Buffer,
UINTN Pages
);
void *

AllocateAlignedPages (
UINTN Pages,
UINTN Alignment
);
void *

AllocateAlignedRuntimePages (
UINTN Pages,
UINTN Alignment
);
void *

AllocateAlignedReservedPages (
UINTN Pages,
UINTN Alignment
);
void

FreeAlignedPages (
void *Buffer,
UINTN Pages
);
void *

AllocatePool (
UINTN AllocationSize
);
void *

AllocateRuntimePool (
UINTN AllocationSize
);
void *

AllocateReservedPool (
UINTN AllocationSize
);
void *

AllocateZeroPool (
UINTN AllocationSize
);
void *

AllocateRuntimeZeroPool (
UINTN AllocationSize
);
void *

AllocateReservedZeroPool (
UINTN AllocationSize
);
void *

AllocateCopyPool (
UINTN AllocationSize,
void *Buffer
);
void *

AllocateRuntimeCopyPool (
UINTN AllocationSize,
void *Buffer
);
void *

AllocateReservedCopyPool (
UINTN AllocationSize,
void *Buffer
);
void *

ReallocatePool (
UINTN OldSize,
UINTN NewSize,
void *OldBuffer
);
void *

ReallocateRuntimePool (
UINTN OldSize,
UINTN NewSize,
void *OldBuffer
);
void *

ReallocateReservedPool (
UINTN OldSize,
UINTN NewSize,
void *OldBuffer
);
void

FreePool (
void *Buffer
);
extern EFI_HANDLE gImageHandle;

extern EFI_SYSTEM_TABLE *gST;

extern EFI_BOOT_SERVICES *gBS;
void

DebugPrint (
UINTN ErrorLevel,
CHAR8 *Format,
...
);
void

DebugAssert (
CHAR8 *FileName,
UINTN LineNumber,
CHAR8 *Description
);
void *

DebugClearMemory (
void *Buffer,
UINTN Length
);
BOOLEAN

DebugAssertEnabled (
void
);
BOOLEAN

DebugPrintEnabled (
void
);
BOOLEAN

DebugCodeEnabled (
void
);
BOOLEAN

DebugClearMemoryEnabled (
void
);

#pragma pack(1)

typedef union {
struct {

UINT8 Header;
UINT8 File;
} Checksum;

UINT16 Checksum16;
} EFI_FFS_INTEGRITY_CHECK;

typedef UINT8 EFI_FV_FILETYPE;
typedef UINT8 EFI_FFS_FILE_ATTRIBUTES;
typedef UINT8 EFI_FFS_FILE_STATE;
typedef struct {

EFI_GUID Name;

EFI_FFS_INTEGRITY_CHECK IntegrityCheck;

EFI_FV_FILETYPE Type;

EFI_FFS_FILE_ATTRIBUTES Attributes;

UINT8 Size[3];

EFI_FFS_FILE_STATE State;
} EFI_FFS_FILE_HEADER;

typedef struct {

EFI_GUID Name;

EFI_FFS_INTEGRITY_CHECK IntegrityCheck;

EFI_FV_FILETYPE Type;

EFI_FFS_FILE_ATTRIBUTES Attributes;
UINT8 Size[3];

EFI_FFS_FILE_STATE State;

UINT32 ExtendedSize;
} EFI_FFS_FILE_HEADER2;
typedef UINT8 EFI_SECTION_TYPE;
typedef struct {

UINT8 Size[3];
EFI_SECTION_TYPE Type;

} EFI_COMMON_SECTION_HEADER;

typedef struct {

UINT8 Size[3];

EFI_SECTION_TYPE Type;

UINT32 ExtendedSize;
} EFI_COMMON_SECTION_HEADER2;

typedef EFI_COMMON_SECTION_HEADER EFI_COMPATIBILITY16_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_COMPATIBILITY16_SECTION2;
typedef struct {

EFI_COMMON_SECTION_HEADER CommonHeader;

UINT32 UncompressedLength;

UINT8 CompressionType;
} EFI_COMPRESSION_SECTION;

typedef struct {

EFI_COMMON_SECTION_HEADER2 CommonHeader;

UINT32 UncompressedLength;

UINT8 CompressionType;
} EFI_COMPRESSION_SECTION2;
typedef EFI_COMMON_SECTION_HEADER EFI_DISPOSABLE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_DISPOSABLE_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_DXE_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_DXE_DEPEX_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_FIRMWARE_VOLUME_IMAGE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_FIRMWARE_VOLUME_IMAGE_SECTION2;

typedef struct {

EFI_COMMON_SECTION_HEADER CommonHeader;

EFI_GUID SubTypeGuid;
} EFI_FREEFORM_SUBTYPE_GUID_SECTION;

typedef struct {

EFI_COMMON_SECTION_HEADER2 CommonHeader;

EFI_GUID SubTypeGuid;
} EFI_FREEFORM_SUBTYPE_GUID_SECTION2;
typedef struct {

EFI_COMMON_SECTION_HEADER CommonHeader;

EFI_GUID SectionDefinitionGuid;

UINT16 DataOffset;

UINT16 Attributes;
} EFI_GUID_DEFINED_SECTION;

typedef struct {

EFI_COMMON_SECTION_HEADER2 CommonHeader;

EFI_GUID SectionDefinitionGuid;

UINT16 DataOffset;

UINT16 Attributes;
} EFI_GUID_DEFINED_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_PE32_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PE32_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_PEI_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PEI_DEPEX_SECTION2;
typedef EFI_COMMON_SECTION_HEADER EFI_PIC_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PIC_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_TE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_TE_SECTION2;

typedef EFI_COMMON_SECTION_HEADER EFI_RAW_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_RAW_SECTION2;
typedef EFI_COMMON_SECTION_HEADER EFI_SMM_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_SMM_DEPEX_SECTION2;

typedef struct {
EFI_COMMON_SECTION_HEADER CommonHeader;

CHAR16 FileNameString[1];
} EFI_USER_INTERFACE_SECTION;

typedef struct {
EFI_COMMON_SECTION_HEADER2 CommonHeader;
CHAR16 FileNameString[1];
} EFI_USER_INTERFACE_SECTION2;

typedef struct {
EFI_COMMON_SECTION_HEADER CommonHeader;
UINT16 BuildNumber;

CHAR16 VersionString[1];
} EFI_VERSION_SECTION;

typedef struct {
EFI_COMMON_SECTION_HEADER2 CommonHeader;

UINT16 BuildNumber;
CHAR16 VersionString[1];
} EFI_VERSION_SECTION2;
#pragma pack()
typedef UINT32 EFI_FV_FILE_ATTRIBUTES;
typedef UINT32 EFI_FVB_ATTRIBUTES_2;
typedef struct {

UINT32 NumBlocks;

UINT32 Length;
} EFI_FV_BLOCK_MAP_ENTRY;

typedef struct {

UINT8 ZeroVector[16];

EFI_GUID FileSystemGuid;

UINT64 FvLength;

UINT32 Signature;

EFI_FVB_ATTRIBUTES_2 Attributes;

UINT16 HeaderLength;

UINT16 Checksum;

UINT16 ExtHeaderOffset;

UINT8 Reserved[1];

UINT8 Revision;

EFI_FV_BLOCK_MAP_ENTRY BlockMap[1];
} EFI_FIRMWARE_VOLUME_HEADER;
typedef struct {

EFI_GUID FvName;

UINT32 ExtHeaderSize;
} EFI_FIRMWARE_VOLUME_EXT_HEADER;

typedef struct {

UINT16 ExtEntrySize;

UINT16 ExtEntryType;
} EFI_FIRMWARE_VOLUME_EXT_ENTRY;

typedef struct {

EFI_FIRMWARE_VOLUME_EXT_ENTRY Hdr;

UINT32 TypeMask;

} EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE;

typedef struct {

EFI_FIRMWARE_VOLUME_EXT_ENTRY Hdr;

EFI_GUID FormatType;

} EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE;

typedef UINT32 EFI_BOOT_MODE;

typedef struct {

UINT16 HobType;

UINT16 HobLength;

UINT32 Reserved;
} EFI_HOB_GENERIC_HEADER;
typedef struct {

EFI_HOB_GENERIC_HEADER Header;

UINT32 Version;

EFI_BOOT_MODE BootMode;

EFI_PHYSICAL_ADDRESS EfiMemoryTop;

EFI_PHYSICAL_ADDRESS EfiMemoryBottom;

EFI_PHYSICAL_ADDRESS EfiFreeMemoryTop;

EFI_PHYSICAL_ADDRESS EfiFreeMemoryBottom;

EFI_PHYSICAL_ADDRESS EfiEndOfHobList;
} EFI_HOB_HANDOFF_INFO_TABLE;

typedef struct {

EFI_GUID Name;

EFI_PHYSICAL_ADDRESS MemoryBaseAddress;

UINT64 MemoryLength;

EFI_MEMORY_TYPE MemoryType;

UINT8 Reserved[4];
} EFI_HOB_MEMORY_ALLOCATION_HEADER;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;

} EFI_HOB_MEMORY_ALLOCATION;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_STACK;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_BSP_STORE;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_HOB_MEMORY_ALLOCATION_HEADER MemoryAllocationHeader;

EFI_GUID ModuleName;

EFI_PHYSICAL_ADDRESS EntryPoint;
} EFI_HOB_MEMORY_ALLOCATION_MODULE;

typedef UINT32 EFI_RESOURCE_TYPE;
typedef UINT32 EFI_RESOURCE_ATTRIBUTE_TYPE;
typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_GUID Owner;

EFI_RESOURCE_TYPE ResourceType;

EFI_RESOURCE_ATTRIBUTE_TYPE ResourceAttribute;

EFI_PHYSICAL_ADDRESS PhysicalStart;

UINT64 ResourceLength;
} EFI_HOB_RESOURCE_DESCRIPTOR;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_GUID Name;

} EFI_HOB_GUID_TYPE;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_PHYSICAL_ADDRESS BaseAddress;

UINT64 Length;
} EFI_HOB_FIRMWARE_VOLUME;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_PHYSICAL_ADDRESS BaseAddress;

UINT64 Length;

EFI_GUID FvName;

EFI_GUID FileName;
} EFI_HOB_FIRMWARE_VOLUME2;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;

UINT8 SizeOfMemorySpace;

UINT8 SizeOfIoSpace;

UINT8 Reserved[6];
} EFI_HOB_CPU;

typedef struct {

EFI_HOB_GENERIC_HEADER Header;
} EFI_HOB_MEMORY_POOL;
typedef struct {

EFI_HOB_GENERIC_HEADER Header;

EFI_PHYSICAL_ADDRESS BaseAddress;
UINT64 Length;
} EFI_HOB_UEFI_CAPSULE;

typedef union {
EFI_HOB_GENERIC_HEADER *Header;
EFI_HOB_HANDOFF_INFO_TABLE *HandoffInformationTable;
EFI_HOB_MEMORY_ALLOCATION *MemoryAllocation;
EFI_HOB_MEMORY_ALLOCATION_BSP_STORE *MemoryAllocationBspStore;
EFI_HOB_MEMORY_ALLOCATION_STACK *MemoryAllocationStack;
EFI_HOB_MEMORY_ALLOCATION_MODULE *MemoryAllocationModule;
EFI_HOB_RESOURCE_DESCRIPTOR *ResourceDescriptor;
EFI_HOB_GUID_TYPE *Guid;
EFI_HOB_FIRMWARE_VOLUME *FirmwareVolume;
EFI_HOB_FIRMWARE_VOLUME2 *FirmwareVolume2;
EFI_HOB_CPU *Cpu;
EFI_HOB_MEMORY_POOL *Pool;
EFI_HOB_UEFI_CAPSULE *Capsule;
UINT8 *Raw;
} EFI_PEI_HOB_POINTERS;

typedef struct {
UINT16 e_magic;
UINT16 e_cblp;
UINT16 e_cp;
UINT16 e_crlc;
UINT16 e_cparhdr;
UINT16 e_minalloc;
UINT16 e_maxalloc;
UINT16 e_ss;
UINT16 e_sp;
UINT16 e_csum;
UINT16 e_ip;
UINT16 e_cs;
UINT16 e_lfarlc;
UINT16 e_ovno;
UINT16 e_res[4];
UINT16 e_oemid;
UINT16 e_oeminfo;
UINT16 e_res2[10];
UINT32 e_lfanew;
} EFI_IMAGE_DOS_HEADER;

typedef struct {
UINT16 Machine;
UINT16 NumberOfSections;
UINT32 TimeDateStamp;
UINT32 PointerToSymbolTable;
UINT32 NumberOfSymbols;
UINT16 SizeOfOptionalHeader;
UINT16 Characteristics;
} EFI_IMAGE_FILE_HEADER;
typedef struct {
UINT32 VirtualAddress;
UINT32 Size;
} EFI_IMAGE_DATA_DIRECTORY;
typedef struct {

UINT16 Magic;
UINT8 MajorLinkerVersion;
UINT8 MinorLinkerVersion;
UINT32 SizeOfCode;
UINT32 SizeOfInitializedData;
UINT32 SizeOfUninitializedData;
UINT32 AddressOfEntryPoint;
UINT32 BaseOfCode;
UINT32 BaseOfData;

UINT32 ImageBase;
UINT32 SectionAlignment;
UINT32 FileAlignment;
UINT16 MajorOperatingSystemVersion;
UINT16 MinorOperatingSystemVersion;
UINT16 MajorImageVersion;
UINT16 MinorImageVersion;
UINT16 MajorSubsystemVersion;
UINT16 MinorSubsystemVersion;
UINT32 Win32VersionValue;
UINT32 SizeOfImage;
UINT32 SizeOfHeaders;
UINT32 CheckSum;
UINT16 Subsystem;
UINT16 DllCharacteristics;
UINT32 SizeOfStackReserve;
UINT32 SizeOfStackCommit;
UINT32 SizeOfHeapReserve;
UINT32 SizeOfHeapCommit;
UINT32 LoaderFlags;
UINT32 NumberOfRvaAndSizes;
EFI_IMAGE_DATA_DIRECTORY DataDirectory[16];
} EFI_IMAGE_OPTIONAL_HEADER32;
typedef struct {

UINT16 Magic;
UINT8 MajorLinkerVersion;
UINT8 MinorLinkerVersion;
UINT32 SizeOfCode;
UINT32 SizeOfInitializedData;
UINT32 SizeOfUninitializedData;
UINT32 AddressOfEntryPoint;
UINT32 BaseOfCode;

UINT64 ImageBase;
UINT32 SectionAlignment;
UINT32 FileAlignment;
UINT16 MajorOperatingSystemVersion;
UINT16 MinorOperatingSystemVersion;
UINT16 MajorImageVersion;
UINT16 MinorImageVersion;
UINT16 MajorSubsystemVersion;
UINT16 MinorSubsystemVersion;
UINT32 Win32VersionValue;
UINT32 SizeOfImage;
UINT32 SizeOfHeaders;
UINT32 CheckSum;
UINT16 Subsystem;
UINT16 DllCharacteristics;
UINT64 SizeOfStackReserve;
UINT64 SizeOfStackCommit;
UINT64 SizeOfHeapReserve;
UINT64 SizeOfHeapCommit;
UINT32 LoaderFlags;
UINT32 NumberOfRvaAndSizes;
EFI_IMAGE_DATA_DIRECTORY DataDirectory[16];
} EFI_IMAGE_OPTIONAL_HEADER64;

typedef struct {
UINT32 Signature;
EFI_IMAGE_FILE_HEADER FileHeader;
EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} EFI_IMAGE_NT_HEADERS32;

typedef struct {
UINT32 Signature;
EFI_IMAGE_FILE_HEADER FileHeader;
EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} EFI_IMAGE_NT_HEADERS64;
typedef struct {
UINT8 Name[8];
union {
UINT32 PhysicalAddress;
UINT32 VirtualSize;
} Misc;
UINT32 VirtualAddress;
UINT32 SizeOfRawData;
UINT32 PointerToRawData;
UINT32 PointerToRelocations;
UINT32 PointerToLinenumbers;
UINT16 NumberOfRelocations;
UINT16 NumberOfLinenumbers;
UINT32 Characteristics;
} EFI_IMAGE_SECTION_HEADER;
typedef struct {
UINT32 VirtualAddress;
UINT32 SymbolTableIndex;
UINT16 Type;
} EFI_IMAGE_RELOCATION;
typedef struct {
UINT32 VirtualAddress;
UINT32 SizeOfBlock;
} EFI_IMAGE_BASE_RELOCATION;
typedef struct {
union {
UINT32 SymbolTableIndex;
UINT32 VirtualAddress;
} Type;
UINT16 Linenumber;
} EFI_IMAGE_LINENUMBER;
typedef struct {
UINT8 Name[16];
UINT8 Date[12];
UINT8 UserID[6];
UINT8 GroupID[6];
UINT8 Mode[8];
UINT8 Size[10];
UINT8 EndHeader[2];
} EFI_IMAGE_ARCHIVE_MEMBER_HEADER;
typedef struct {
UINT32 Characteristics;
UINT32 TimeDateStamp;
UINT16 MajorVersion;
UINT16 MinorVersion;
UINT32 Name;
UINT32 Base;
UINT32 NumberOfFunctions;
UINT32 NumberOfNames;
UINT32 AddressOfFunctions;
UINT32 AddressOfNames;
UINT32 AddressOfNameOrdinals;
} EFI_IMAGE_EXPORT_DIRECTORY;

typedef struct {
UINT16 Hint;
UINT8 Name[1];
} EFI_IMAGE_IMPORT_BY_NAME;

typedef struct {
union {
UINT32 Function;
UINT32 Ordinal;
EFI_IMAGE_IMPORT_BY_NAME *AddressOfData;
} u1;
} EFI_IMAGE_THUNK_DATA;
typedef struct {
UINT32 Characteristics;
UINT32 TimeDateStamp;
UINT32 ForwarderChain;
UINT32 Name;
EFI_IMAGE_THUNK_DATA *FirstThunk;
} EFI_IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
UINT32 Characteristics;
UINT32 TimeDateStamp;
UINT16 MajorVersion;
UINT16 MinorVersion;
UINT32 Type;
UINT32 SizeOfData;
UINT32 RVA;
UINT32 FileOffset;
} EFI_IMAGE_DEBUG_DIRECTORY_ENTRY;

typedef struct {
UINT32 Signature;
UINT32 Unknown;
UINT32 Unknown2;
UINT32 Unknown3;

} EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY;

typedef struct {
UINT32 Signature;
UINT32 Unknown;
UINT32 Unknown2;
UINT32 Unknown3;
UINT32 Unknown4;
UINT32 Unknown5;

} EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY;

typedef struct {
UINT32 Signature;
GUID MachOUuid;

} EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY;

typedef struct {
UINT32 Characteristics;
UINT32 TimeDateStamp;
UINT16 MajorVersion;
UINT16 MinorVersion;
UINT16 NumberOfNamedEntries;
UINT16 NumberOfIdEntries;

} EFI_IMAGE_RESOURCE_DIRECTORY;

typedef struct {
union {
struct {
UINT32 NameOffset:31;
UINT32 NameIsString:1;
} s;
UINT32 Id;
} u1;
union {
UINT32 OffsetToData;
struct {
UINT32 OffsetToDirectory:31;
UINT32 DataIsDirectory:1;
} s;
} u2;
} EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct {
UINT16 Length;
CHAR16 String[1];
} EFI_IMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct {
UINT32 OffsetToData;
UINT32 Size;
UINT32 CodePage;
UINT32 Reserved;
} EFI_IMAGE_RESOURCE_DATA_ENTRY;

typedef struct {
UINT16 Signature;
UINT16 Machine;
UINT8 NumberOfSections;
UINT8 Subsystem;
UINT16 StrippedSize;
UINT32 AddressOfEntryPoint;
UINT32 BaseOfCode;
UINT64 ImageBase;
EFI_IMAGE_DATA_DIRECTORY DataDirectory[2];
} EFI_TE_IMAGE_HEADER;
typedef union {
EFI_IMAGE_NT_HEADERS32 Pe32;
EFI_IMAGE_NT_HEADERS64 Pe32Plus;
EFI_TE_IMAGE_HEADER Te;
} EFI_IMAGE_OPTIONAL_HEADER_UNION;

typedef union {
EFI_IMAGE_NT_HEADERS32 *Pe32;
EFI_IMAGE_NT_HEADERS64 *Pe32Plus;
EFI_TE_IMAGE_HEADER *Te;
EFI_IMAGE_OPTIONAL_HEADER_UNION *Union;
} EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION;

typedef struct _EFI_DEBUG_SUPPORT_PROTOCOL EFI_DEBUG_SUPPORT_PROTOCOL;
typedef INTN EFI_EXCEPTION_TYPE;
typedef struct {
UINT16 Fcw;
UINT16 Fsw;
UINT16 Ftw;
UINT16 Opcode;
UINT32 Eip;
UINT16 Cs;
UINT16 Reserved1;
UINT32 DataOffset;
UINT16 Ds;
UINT8 Reserved2[10];
UINT8 St0Mm0[10], Reserved3[6];
UINT8 St1Mm1[10], Reserved4[6];
UINT8 St2Mm2[10], Reserved5[6];
UINT8 St3Mm3[10], Reserved6[6];
UINT8 St4Mm4[10], Reserved7[6];
UINT8 St5Mm5[10], Reserved8[6];
UINT8 St6Mm6[10], Reserved9[6];
UINT8 St7Mm7[10], Reserved10[6];
UINT8 Xmm0[16];
UINT8 Xmm1[16];
UINT8 Xmm2[16];
UINT8 Xmm3[16];
UINT8 Xmm4[16];
UINT8 Xmm5[16];
UINT8 Xmm6[16];
UINT8 Xmm7[16];
UINT8 Reserved11[14 * 16];
} EFI_FX_SAVE_STATE_IA32;

typedef struct {
UINT32 ExceptionData;
EFI_FX_SAVE_STATE_IA32 FxSaveState;
UINT32 Dr0;
UINT32 Dr1;
UINT32 Dr2;
UINT32 Dr3;
UINT32 Dr6;
UINT32 Dr7;
UINT32 Cr0;
UINT32 Cr1;
UINT32 Cr2;
UINT32 Cr3;
UINT32 Cr4;
UINT32 Eflags;
UINT32 Ldtr;
UINT32 Tr;
UINT32 Gdtr[2];
UINT32 Idtr[2];
UINT32 Eip;
UINT32 Gs;
UINT32 Fs;
UINT32 Es;
UINT32 Ds;
UINT32 Cs;
UINT32 Ss;
UINT32 Edi;
UINT32 Esi;
UINT32 Ebp;
UINT32 Esp;
UINT32 Ebx;
UINT32 Edx;
UINT32 Ecx;
UINT32 Eax;
} EFI_SYSTEM_CONTEXT_IA32;
typedef struct {
UINT16 Fcw;
UINT16 Fsw;
UINT16 Ftw;
UINT16 Opcode;
UINT64 Rip;
UINT64 DataOffset;
UINT8 Reserved1[8];
UINT8 St0Mm0[10], Reserved2[6];
UINT8 St1Mm1[10], Reserved3[6];
UINT8 St2Mm2[10], Reserved4[6];
UINT8 St3Mm3[10], Reserved5[6];
UINT8 St4Mm4[10], Reserved6[6];
UINT8 St5Mm5[10], Reserved7[6];
UINT8 St6Mm6[10], Reserved8[6];
UINT8 St7Mm7[10], Reserved9[6];
UINT8 Xmm0[16];
UINT8 Xmm1[16];
UINT8 Xmm2[16];
UINT8 Xmm3[16];
UINT8 Xmm4[16];
UINT8 Xmm5[16];
UINT8 Xmm6[16];
UINT8 Xmm7[16];

UINT8 Reserved11[14 * 16];
} EFI_FX_SAVE_STATE_X64;

typedef struct {
UINT64 ExceptionData;
EFI_FX_SAVE_STATE_X64 FxSaveState;
UINT64 Dr0;
UINT64 Dr1;
UINT64 Dr2;
UINT64 Dr3;
UINT64 Dr6;
UINT64 Dr7;
UINT64 Cr0;
UINT64 Cr1;
UINT64 Cr2;
UINT64 Cr3;
UINT64 Cr4;
UINT64 Cr8;
UINT64 Rflags;
UINT64 Ldtr;
UINT64 Tr;
UINT64 Gdtr[2];
UINT64 Idtr[2];
UINT64 Rip;
UINT64 Gs;
UINT64 Fs;
UINT64 Es;
UINT64 Ds;
UINT64 Cs;
UINT64 Ss;
UINT64 Rdi;
UINT64 Rsi;
UINT64 Rbp;
UINT64 Rsp;
UINT64 Rbx;
UINT64 Rdx;
UINT64 Rcx;
UINT64 Rax;
UINT64 R8;
UINT64 R9;
UINT64 R10;
UINT64 R11;
UINT64 R12;
UINT64 R13;
UINT64 R14;
UINT64 R15;
} EFI_SYSTEM_CONTEXT_X64;
typedef struct {

UINT64 Reserved;
UINT64 R1;
UINT64 R2;
UINT64 R3;
UINT64 R4;
UINT64 R5;
UINT64 R6;
UINT64 R7;
UINT64 R8;
UINT64 R9;
UINT64 R10;
UINT64 R11;
UINT64 R12;
UINT64 R13;
UINT64 R14;
UINT64 R15;
UINT64 R16;
UINT64 R17;
UINT64 R18;
UINT64 R19;
UINT64 R20;
UINT64 R21;
UINT64 R22;
UINT64 R23;
UINT64 R24;
UINT64 R25;
UINT64 R26;
UINT64 R27;
UINT64 R28;
UINT64 R29;
UINT64 R30;
UINT64 R31;

UINT64 F2[2];
UINT64 F3[2];
UINT64 F4[2];
UINT64 F5[2];
UINT64 F6[2];
UINT64 F7[2];
UINT64 F8[2];
UINT64 F9[2];
UINT64 F10[2];
UINT64 F11[2];
UINT64 F12[2];
UINT64 F13[2];
UINT64 F14[2];
UINT64 F15[2];
UINT64 F16[2];
UINT64 F17[2];
UINT64 F18[2];
UINT64 F19[2];
UINT64 F20[2];
UINT64 F21[2];
UINT64 F22[2];
UINT64 F23[2];
UINT64 F24[2];
UINT64 F25[2];
UINT64 F26[2];
UINT64 F27[2];
UINT64 F28[2];
UINT64 F29[2];
UINT64 F30[2];
UINT64 F31[2];

UINT64 Pr;

UINT64 B0;
UINT64 B1;
UINT64 B2;
UINT64 B3;
UINT64 B4;
UINT64 B5;
UINT64 B6;
UINT64 B7;

UINT64 ArRsc;
UINT64 ArBsp;
UINT64 ArBspstore;
UINT64 ArRnat;

UINT64 ArFcr;

UINT64 ArEflag;
UINT64 ArCsd;
UINT64 ArSsd;
UINT64 ArCflg;
UINT64 ArFsr;
UINT64 ArFir;
UINT64 ArFdr;

UINT64 ArCcv;

UINT64 ArUnat;

UINT64 ArFpsr;

UINT64 ArPfs;
UINT64 ArLc;
UINT64 ArEc;

UINT64 CrDcr;
UINT64 CrItm;
UINT64 CrIva;
UINT64 CrPta;
UINT64 CrIpsr;
UINT64 CrIsr;
UINT64 CrIip;
UINT64 CrIfa;
UINT64 CrItir;
UINT64 CrIipa;
UINT64 CrIfs;
UINT64 CrIim;
UINT64 CrIha;

UINT64 Dbr0;
UINT64 Dbr1;
UINT64 Dbr2;
UINT64 Dbr3;
UINT64 Dbr4;
UINT64 Dbr5;
UINT64 Dbr6;
UINT64 Dbr7;

UINT64 Ibr0;
UINT64 Ibr1;
UINT64 Ibr2;
UINT64 Ibr3;
UINT64 Ibr4;
UINT64 Ibr5;
UINT64 Ibr6;
UINT64 Ibr7;

UINT64 IntNat;

} EFI_SYSTEM_CONTEXT_IPF;
typedef struct {
UINT64 R0;
UINT64 R1;
UINT64 R2;
UINT64 R3;
UINT64 R4;
UINT64 R5;
UINT64 R6;
UINT64 R7;
UINT64 Flags;
UINT64 ControlFlags;
UINT64 Ip;
} EFI_SYSTEM_CONTEXT_EBC;
typedef struct {
UINT32 R0;
UINT32 R1;
UINT32 R2;
UINT32 R3;
UINT32 R4;
UINT32 R5;
UINT32 R6;
UINT32 R7;
UINT32 R8;
UINT32 R9;
UINT32 R10;
UINT32 R11;
UINT32 R12;
UINT32 SP;
UINT32 LR;
UINT32 PC;
UINT32 CPSR;
UINT32 DFSR;
UINT32 DFAR;
UINT32 IFSR;
UINT32 IFAR;
} EFI_SYSTEM_CONTEXT_ARM;

typedef union {
EFI_SYSTEM_CONTEXT_EBC *SystemContextEbc;
EFI_SYSTEM_CONTEXT_IA32 *SystemContextIa32;
EFI_SYSTEM_CONTEXT_X64 *SystemContextX64;
EFI_SYSTEM_CONTEXT_IPF *SystemContextIpf;
EFI_SYSTEM_CONTEXT_ARM *SystemContextArm;
} EFI_SYSTEM_CONTEXT;
typedef
void
( *EFI_EXCEPTION_CALLBACK)(
EFI_EXCEPTION_TYPE ExceptionType,
EFI_SYSTEM_CONTEXT SystemContext
);

typedef
void
( *EFI_PERIODIC_CALLBACK)(
EFI_SYSTEM_CONTEXT SystemContext
);

typedef enum {
IsaIa32 = 0x014c,
IsaX64 = 0x8664,
IsaIpf = 0x0200,
IsaEbc = 0x0EBC,
IsaArm = 0x01c2
} EFI_INSTRUCTION_SET_ARCHITECTURE;
typedef
EFI_STATUS
( *EFI_GET_MAXIMUM_PROCESSOR_INDEX)(
EFI_DEBUG_SUPPORT_PROTOCOL *This,
UINTN *MaxProcessorIndex
);
typedef
EFI_STATUS
( *EFI_REGISTER_PERIODIC_CALLBACK)(
EFI_DEBUG_SUPPORT_PROTOCOL *This,
UINTN ProcessorIndex,
EFI_PERIODIC_CALLBACK PeriodicCallback
);
typedef
EFI_STATUS
( *EFI_REGISTER_EXCEPTION_CALLBACK)(
EFI_DEBUG_SUPPORT_PROTOCOL *This,
UINTN ProcessorIndex,
EFI_EXCEPTION_CALLBACK ExceptionCallback,
EFI_EXCEPTION_TYPE ExceptionType
);
typedef
EFI_STATUS
( *EFI_INVALIDATE_INSTRUCTION_CACHE)(
EFI_DEBUG_SUPPORT_PROTOCOL *This,
UINTN ProcessorIndex,
void *Start,
UINT64 Length
);

struct _EFI_DEBUG_SUPPORT_PROTOCOL {

EFI_INSTRUCTION_SET_ARCHITECTURE Isa;
EFI_GET_MAXIMUM_PROCESSOR_INDEX GetMaximumProcessorIndex;
EFI_REGISTER_PERIODIC_CALLBACK RegisterPeriodicCallback;
EFI_REGISTER_EXCEPTION_CALLBACK RegisterExceptionCallback;
EFI_INVALIDATE_INSTRUCTION_CACHE InvalidateInstructionCache;
};

extern EFI_GUID gEfiDebugSupportProtocolGuid;

typedef UINT32 EFI_STATUS_CODE_TYPE;
typedef UINT32 EFI_STATUS_CODE_VALUE;
typedef struct {

UINT16 HeaderSize;

UINT16 Size;

EFI_GUID Type;
} EFI_STATUS_CODE_DATA;

typedef enum {
EfiBootScriptWidthUint8,
EfiBootScriptWidthUint16,
EfiBootScriptWidthUint32,
EfiBootScriptWidthUint64,
EfiBootScriptWidthFifoUint8,
EfiBootScriptWidthFifoUint16,
EfiBootScriptWidthFifoUint32,
EfiBootScriptWidthFifoUint64,
EfiBootScriptWidthFillUint8,
EfiBootScriptWidthFillUint16,
EfiBootScriptWidthFillUint32,
EfiBootScriptWidthFillUint64,
EfiBootScriptWidthMaximum
} EFI_BOOT_SCRIPT_WIDTH;
typedef struct {

EFI_PHYSICAL_ADDRESS PhysicalStart;

EFI_PHYSICAL_ADDRESS CpuStart;

UINT64 PhysicalSize;

UINT64 RegionState;
} EFI_SMRAM_DESCRIPTOR;

typedef enum {

EfiGcdMemoryTypeNonExistent,

EfiGcdMemoryTypeReserved,

EfiGcdMemoryTypeSystemMemory,

EfiGcdMemoryTypeMemoryMappedIo,
EfiGcdMemoryTypeMaximum
} EFI_GCD_MEMORY_TYPE;

typedef enum {

EfiGcdIoTypeNonExistent,

EfiGcdIoTypeReserved,

EfiGcdIoTypeIo,
EfiGcdIoTypeMaximum
} EFI_GCD_IO_TYPE;

typedef enum {

EfiGcdAllocateAnySearchBottomUp,

EfiGcdAllocateMaxAddressSearchBottomUp,

EfiGcdAllocateAddress,

EfiGcdAllocateAnySearchTopDown,

EfiGcdAllocateMaxAddressSearchTopDown,
EfiGcdMaxAllocateType
} EFI_GCD_ALLOCATE_TYPE;

typedef struct {

EFI_PHYSICAL_ADDRESS BaseAddress;

UINT64 Length;

UINT64 Capabilities;

UINT64 Attributes;

EFI_GCD_MEMORY_TYPE GcdMemoryType;

EFI_HANDLE ImageHandle;
EFI_HANDLE DeviceHandle;
} EFI_GCD_MEMORY_SPACE_DESCRIPTOR;

typedef struct {

EFI_PHYSICAL_ADDRESS BaseAddress;

UINT64 Length;

EFI_GCD_IO_TYPE GcdIoType;

EFI_HANDLE ImageHandle;
EFI_HANDLE DeviceHandle;
} EFI_GCD_IO_SPACE_DESCRIPTOR;
typedef
EFI_STATUS
( *EFI_ADD_MEMORY_SPACE)(
EFI_GCD_MEMORY_TYPE GcdMemoryType,
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length,
UINT64 Capabilities
);
typedef
EFI_STATUS
( *EFI_ALLOCATE_MEMORY_SPACE)(
EFI_GCD_ALLOCATE_TYPE GcdAllocateType,
EFI_GCD_MEMORY_TYPE GcdMemoryType,
UINTN Alignment,
UINT64 Length,
EFI_PHYSICAL_ADDRESS *BaseAddress,
EFI_HANDLE ImageHandle,
EFI_HANDLE DeviceHandle
);
typedef
EFI_STATUS
( *EFI_FREE_MEMORY_SPACE)(
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_REMOVE_MEMORY_SPACE)(
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_GET_MEMORY_SPACE_DESCRIPTOR)(
EFI_PHYSICAL_ADDRESS BaseAddress,
EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Descriptor
);
typedef
EFI_STATUS
( *EFI_SET_MEMORY_SPACE_ATTRIBUTES)(
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length,
UINT64 Attributes
);
typedef
EFI_STATUS
( *EFI_GET_MEMORY_SPACE_MAP)(
UINTN *NumberOfDescriptors,
EFI_GCD_MEMORY_SPACE_DESCRIPTOR **MemorySpaceMap
);
typedef
EFI_STATUS
( *EFI_ADD_IO_SPACE)(
EFI_GCD_IO_TYPE GcdIoType,
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_ALLOCATE_IO_SPACE)(
EFI_GCD_ALLOCATE_TYPE GcdAllocateType,
EFI_GCD_IO_TYPE GcdIoType,
UINTN Alignment,
UINT64 Length,
EFI_PHYSICAL_ADDRESS *BaseAddress,
EFI_HANDLE ImageHandle,
EFI_HANDLE DeviceHandle
);
typedef
EFI_STATUS
( *EFI_FREE_IO_SPACE)(
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_REMOVE_IO_SPACE)(
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_GET_IO_SPACE_DESCRIPTOR)(
EFI_PHYSICAL_ADDRESS BaseAddress,
EFI_GCD_IO_SPACE_DESCRIPTOR *Descriptor
);
typedef
EFI_STATUS
( *EFI_GET_IO_SPACE_MAP)(
UINTN *NumberOfDescriptors,
EFI_GCD_IO_SPACE_DESCRIPTOR **IoSpaceMap
);
typedef
EFI_STATUS
( *EFI_DISPATCH)(
void
);
typedef
EFI_STATUS
( *EFI_SCHEDULE)(
EFI_HANDLE FirmwareVolumeHandle,
EFI_GUID *FileName
);
typedef
EFI_STATUS
( *EFI_TRUST)(
EFI_HANDLE FirmwareVolumeHandle,
EFI_GUID *FileName
);
typedef
EFI_STATUS
( *EFI_PROCESS_FIRMWARE_VOLUME)(
void *FirmwareVolumeHeader,
UINTN Size,
EFI_HANDLE *FirmwareVolumeHandle
);
typedef struct {

EFI_TABLE_HEADER Hdr;

EFI_ADD_MEMORY_SPACE AddMemorySpace;
EFI_ALLOCATE_MEMORY_SPACE AllocateMemorySpace;
EFI_FREE_MEMORY_SPACE FreeMemorySpace;
EFI_REMOVE_MEMORY_SPACE RemoveMemorySpace;
EFI_GET_MEMORY_SPACE_DESCRIPTOR GetMemorySpaceDescriptor;
EFI_SET_MEMORY_SPACE_ATTRIBUTES SetMemorySpaceAttributes;
EFI_GET_MEMORY_SPACE_MAP GetMemorySpaceMap;
EFI_ADD_IO_SPACE AddIoSpace;
EFI_ALLOCATE_IO_SPACE AllocateIoSpace;
EFI_FREE_IO_SPACE FreeIoSpace;
EFI_REMOVE_IO_SPACE RemoveIoSpace;
EFI_GET_IO_SPACE_DESCRIPTOR GetIoSpaceDescriptor;
EFI_GET_IO_SPACE_MAP GetIoSpaceMap;

EFI_DISPATCH Dispatch;
EFI_SCHEDULE Schedule;
EFI_TRUST Trust;

EFI_PROCESS_FIRMWARE_VOLUME ProcessFirmwareVolume;
} DXE_SERVICES;

typedef DXE_SERVICES EFI_DXE_SERVICES;
typedef
void
( *EFI_AP_PROCEDURE)(
void *Buffer
);

typedef struct _EFI_ABSOLUTE_POINTER_PROTOCOL EFI_ABSOLUTE_POINTER_PROTOCOL;
typedef struct {
UINT64 AbsoluteMinX;
UINT64 AbsoluteMinY;
UINT64 AbsoluteMinZ;
UINT64 AbsoluteMaxX;

UINT64 AbsoluteMaxY;

UINT64 AbsoluteMaxZ;

UINT32 Attributes;

} EFI_ABSOLUTE_POINTER_MODE;
typedef
EFI_STATUS
( *EFI_ABSOLUTE_POINTER_RESET)(
EFI_ABSOLUTE_POINTER_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef struct {

UINT64 CurrentX;

UINT64 CurrentY;

UINT64 CurrentZ;

UINT32 ActiveButtons;
} EFI_ABSOLUTE_POINTER_STATE;
typedef
EFI_STATUS
( *EFI_ABSOLUTE_POINTER_GET_STATE)(
EFI_ABSOLUTE_POINTER_PROTOCOL *This,
EFI_ABSOLUTE_POINTER_STATE *State
);
struct _EFI_ABSOLUTE_POINTER_PROTOCOL {
EFI_ABSOLUTE_POINTER_RESET Reset;
EFI_ABSOLUTE_POINTER_GET_STATE GetState;

EFI_EVENT WaitForInput;

EFI_ABSOLUTE_POINTER_MODE *Mode;
};

extern EFI_GUID gEfiAbsolutePointerProtocolGuid;
typedef UINT32 EFI_ACPI_TABLE_VERSION;
typedef void *EFI_ACPI_HANDLE;

typedef UINT32 EFI_ACPI_DATA_TYPE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT8 Revision;
UINT8 Checksum;
CHAR8 OemId[6];
CHAR8 OemTableId[8];
UINT32 OemRevision;
UINT32 CreatorId;
UINT32 CreatorRevision;
} EFI_ACPI_SDT_HEADER;

typedef
EFI_STATUS
( *EFI_ACPI_NOTIFICATION_FN)(
EFI_ACPI_SDT_HEADER *Table,
EFI_ACPI_TABLE_VERSION Version,
UINTN TableKey
);
typedef
EFI_STATUS
( *EFI_ACPI_GET_ACPI_TABLE2)(
UINTN Index,
EFI_ACPI_SDT_HEADER **Table,
EFI_ACPI_TABLE_VERSION *Version,
UINTN *TableKey
);
typedef
EFI_STATUS
( *EFI_ACPI_REGISTER_NOTIFY)(
BOOLEAN Register,
EFI_ACPI_NOTIFICATION_FN Notification
);
typedef
EFI_STATUS
( *EFI_ACPI_OPEN)(
void *Buffer,
EFI_ACPI_HANDLE *Handle
);
typedef
EFI_STATUS
( *EFI_ACPI_OPEN_SDT)(
UINTN TableKey,
EFI_ACPI_HANDLE *Handle
);
typedef
EFI_STATUS
( *EFI_ACPI_CLOSE)(
EFI_ACPI_HANDLE Handle
);
typedef
EFI_STATUS
( *EFI_ACPI_GET_CHILD)(
EFI_ACPI_HANDLE ParentHandle,
EFI_ACPI_HANDLE *Handle
);
typedef
EFI_STATUS
( *EFI_ACPI_GET_OPTION)(
EFI_ACPI_HANDLE Handle,
UINTN Index,
EFI_ACPI_DATA_TYPE *DataType,
void **Data,
UINTN *DataSize
);
typedef
EFI_STATUS
( *EFI_ACPI_SET_OPTION)(
EFI_ACPI_HANDLE Handle,
UINTN Index,
void *Data,
UINTN DataSize
);
typedef
EFI_STATUS
( *EFI_ACPI_FIND_PATH)(
EFI_ACPI_HANDLE HandleIn,
void *AcpiPath,
EFI_ACPI_HANDLE *HandleOut
);

typedef struct _EFI_ACPI_SDT_PROTOCOL {

EFI_ACPI_TABLE_VERSION AcpiVersion;
EFI_ACPI_GET_ACPI_TABLE2 GetAcpiTable;
EFI_ACPI_REGISTER_NOTIFY RegisterNotify;
EFI_ACPI_OPEN Open;
EFI_ACPI_OPEN_SDT OpenSdt;
EFI_ACPI_CLOSE Close;
EFI_ACPI_GET_CHILD GetChild;
EFI_ACPI_GET_OPTION GetOption;
EFI_ACPI_SET_OPTION SetOption;
EFI_ACPI_FIND_PATH FindPath;
} EFI_ACPI_SDT_PROTOCOL;

extern EFI_GUID gEfiAcpiSdtProtocolGuid;
typedef struct _EFI_ACPI_TABLE_PROTOCOL EFI_ACPI_TABLE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_ACPI_TABLE_INSTALL_ACPI_TABLE)(
EFI_ACPI_TABLE_PROTOCOL *This,
void *AcpiTableBuffer,
UINTN AcpiTableBufferSize,
UINTN *TableKey
);
typedef
EFI_STATUS
( *EFI_ACPI_TABLE_UNINSTALL_ACPI_TABLE)(
EFI_ACPI_TABLE_PROTOCOL *This,
UINTN TableKey
);

typedef struct _EFI_ACPI_TABLE_PROTOCOL {
EFI_ACPI_TABLE_INSTALL_ACPI_TABLE InstallAcpiTable;
EFI_ACPI_TABLE_UNINSTALL_ACPI_TABLE UninstallAcpiTable;
} EFI_ACPI_TABLE_PROTOCOL;

extern EFI_GUID gEfiAcpiTableProtocolGuid;
typedef struct _EFI_ARP_PROTOCOL EFI_ARP_PROTOCOL;

typedef struct {

UINT32 Size;

BOOLEAN DenyFlag;

BOOLEAN StaticFlag;

UINT16 HwAddressType;

UINT16 SwAddressType;

UINT8 HwAddressLength;

UINT8 SwAddressLength;
} EFI_ARP_FIND_DATA;

typedef struct {

UINT16 SwAddressType;

UINT8 SwAddressLength;

void *StationAddress;

UINT32 EntryTimeOut;

UINT32 RetryCount;

UINT32 RetryTimeOut;
} EFI_ARP_CONFIG_DATA;
typedef
EFI_STATUS
( *EFI_ARP_CONFIGURE)(
EFI_ARP_PROTOCOL *This,
EFI_ARP_CONFIG_DATA *ConfigData
);
typedef
EFI_STATUS
( *EFI_ARP_ADD)(
EFI_ARP_PROTOCOL *This,
BOOLEAN DenyFlag,
void *TargetSwAddress ,
void *TargetHwAddress ,
UINT32 TimeoutValue,
BOOLEAN Overwrite
);
typedef
EFI_STATUS
( *EFI_ARP_FIND)(
EFI_ARP_PROTOCOL *This,
BOOLEAN BySwAddress,
void *AddressBuffer ,
UINT32 *EntryLength ,
UINT32 *EntryCount ,
EFI_ARP_FIND_DATA **Entries ,
BOOLEAN Refresh
);
typedef
EFI_STATUS
( *EFI_ARP_DELETE)(
EFI_ARP_PROTOCOL *This,
BOOLEAN BySwAddress,
void *AddressBuffer
);
typedef
EFI_STATUS
( *EFI_ARP_FLUSH)(
EFI_ARP_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_ARP_REQUEST)(
EFI_ARP_PROTOCOL *This,
void *TargetSwAddress ,
EFI_EVENT ResolvedEvent ,
void *TargetHwAddress
);
typedef
EFI_STATUS
( *EFI_ARP_CANCEL)(
EFI_ARP_PROTOCOL *This,
void *TargetSwAddress ,
EFI_EVENT ResolvedEvent
);

struct _EFI_ARP_PROTOCOL {
EFI_ARP_CONFIGURE Configure;
EFI_ARP_ADD Add;
EFI_ARP_FIND Find;
EFI_ARP_DELETE Delete;
EFI_ARP_FLUSH Flush;
EFI_ARP_REQUEST Request;
EFI_ARP_CANCEL Cancel;
};

extern EFI_GUID gEfiArpServiceBindingProtocolGuid;
extern EFI_GUID gEfiArpProtocolGuid;
typedef struct _EFI_ATA_PASS_THRU_PROTOCOL EFI_ATA_PASS_THRU_PROTOCOL;

typedef struct {
UINT32 Attributes;
UINT32 IoAlign;
} EFI_ATA_PASS_THRU_MODE;
typedef struct _EFI_ATA_COMMAND_BLOCK {
UINT8 Reserved1[2];
UINT8 AtaCommand;
UINT8 AtaFeatures;
UINT8 AtaSectorNumber;
UINT8 AtaCylinderLow;
UINT8 AtaCylinderHigh;
UINT8 AtaDeviceHead;
UINT8 AtaSectorNumberExp;
UINT8 AtaCylinderLowExp;
UINT8 AtaCylinderHighExp;
UINT8 AtaFeaturesExp;
UINT8 AtaSectorCount;
UINT8 AtaSectorCountExp;
UINT8 Reserved2[6];
} EFI_ATA_COMMAND_BLOCK;

typedef struct _EFI_ATA_STATUS_BLOCK {
UINT8 Reserved1[2];
UINT8 AtaStatus;
UINT8 AtaError;
UINT8 AtaSectorNumber;
UINT8 AtaCylinderLow;
UINT8 AtaCylinderHigh;
UINT8 AtaDeviceHead;
UINT8 AtaSectorNumberExp;
UINT8 AtaCylinderLowExp;
UINT8 AtaCylinderHighExp;
UINT8 Reserved2;
UINT8 AtaSectorCount;
UINT8 AtaSectorCountExp;
UINT8 Reserved3[6];
} EFI_ATA_STATUS_BLOCK;

typedef UINT8 EFI_ATA_PASS_THRU_CMD_PROTOCOL;
typedef UINT8 EFI_ATA_PASS_THRU_LENGTH;
typedef struct {

EFI_ATA_STATUS_BLOCK *Asb;

EFI_ATA_COMMAND_BLOCK *Acb;

UINT64 Timeout;

void *InDataBuffer;

void *OutDataBuffer;

UINT32 InTransferLength;

UINT32 OutTransferLength;

EFI_ATA_PASS_THRU_CMD_PROTOCOL Protocol;

EFI_ATA_PASS_THRU_LENGTH Length;
} EFI_ATA_PASS_THRU_COMMAND_PACKET;
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_PASSTHRU)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 Port,
UINT16 PortMultiplierPort,
EFI_ATA_PASS_THRU_COMMAND_PACKET *Packet,
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_GET_NEXT_PORT)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 *Port
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_GET_NEXT_DEVICE)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 Port,
UINT16 *PortMultiplierPort
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_BUILD_DEVICE_PATH)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 Port,
UINT16 PortMultiplierPort,
EFI_DEVICE_PATH_PROTOCOL **DevicePath
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_GET_DEVICE)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
UINT16 *Port,
UINT16 *PortMultiplierPort
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_RESET_PORT)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 Port
);
typedef
EFI_STATUS
( *EFI_ATA_PASS_THRU_RESET_DEVICE)(
EFI_ATA_PASS_THRU_PROTOCOL *This,
UINT16 Port,
UINT16 PortMultiplierPort
);

struct _EFI_ATA_PASS_THRU_PROTOCOL {
EFI_ATA_PASS_THRU_MODE *Mode;
EFI_ATA_PASS_THRU_PASSTHRU PassThru;
EFI_ATA_PASS_THRU_GET_NEXT_PORT GetNextPort;
EFI_ATA_PASS_THRU_GET_NEXT_DEVICE GetNextDevice;
EFI_ATA_PASS_THRU_BUILD_DEVICE_PATH BuildDevicePath;
EFI_ATA_PASS_THRU_GET_DEVICE GetDevice;
EFI_ATA_PASS_THRU_RESET_PORT ResetPort;
EFI_ATA_PASS_THRU_RESET_DEVICE ResetDevice;
};

extern EFI_GUID gEfiAtaPassThruProtocolGuid;
typedef struct _EFI_AUTHENTICATION_INFO_PROTOCOL EFI_AUTHENTICATION_INFO_PROTOCOL;

#pragma pack(1)
typedef struct {

EFI_GUID Guid;

UINT16 Length;
} AUTH_NODE_HEADER;

typedef struct {
AUTH_NODE_HEADER Header;

UINT8 RadiusIpAddr[16];

UINT16 Reserved;

UINT8 NasIpAddr[16];

UINT16 NasSecretLength;

UINT8 NasSecret[1];
} CHAP_RADIUS_AUTH_NODE;

typedef struct {
AUTH_NODE_HEADER Header;

UINT16 Reserved;

UINT16 UserSecretLength;

UINT8 UserSecret[1];
} CHAP_LOCAL_AUTH_NODE;
#pragma pack()
typedef
EFI_STATUS
( *EFI_AUTHENTICATION_INFO_PROTOCOL_GET)(
EFI_AUTHENTICATION_INFO_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
void **Buffer
);
typedef
EFI_STATUS
( *EFI_AUTHENTICATION_INFO_PROTOCOL_SET)(
EFI_AUTHENTICATION_INFO_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
void *Buffer
);

struct _EFI_AUTHENTICATION_INFO_PROTOCOL {
EFI_AUTHENTICATION_INFO_PROTOCOL_GET Get;
EFI_AUTHENTICATION_INFO_PROTOCOL_SET Set;
};

extern EFI_GUID gEfiAuthenticationInfoProtocolGuid;
extern EFI_GUID gEfiAuthenticationChapRadiusGuid;
extern EFI_GUID gEfiAuthenticationChapLocalGuid;
typedef struct _EFI_BDS_ARCH_PROTOCOL EFI_BDS_ARCH_PROTOCOL;
typedef
void
( *EFI_BDS_ENTRY)(
EFI_BDS_ARCH_PROTOCOL *This
);
struct _EFI_BDS_ARCH_PROTOCOL {
EFI_BDS_ENTRY Entry;
};

extern EFI_GUID gEfiBdsArchProtocolGuid;
typedef struct _EFI_BIS_PROTOCOL EFI_BIS_PROTOCOL;

typedef void *BIS_APPLICATION_HANDLE;
typedef UINT16 BIS_ALG_ID;
typedef UINT32 BIS_CERT_ID;

typedef struct {
UINT32 Length;
UINT8 *Data;
} EFI_BIS_DATA;

typedef struct {
UINT32 Major;
UINT32 Minor;
} EFI_BIS_VERSION;
typedef struct {
BIS_CERT_ID CertificateID;
BIS_ALG_ID AlgorithmID;
UINT16 KeyLength;
} EFI_BIS_SIGNATURE_INFO;
typedef
EFI_STATUS
( *EFI_BIS_INITIALIZE)(
EFI_BIS_PROTOCOL *This,
BIS_APPLICATION_HANDLE *AppHandle,
EFI_BIS_VERSION *InterfaceVersion,
EFI_BIS_DATA *TargetAddress
);
typedef
EFI_STATUS
( *EFI_BIS_FREE)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA *ToFree
);
typedef
EFI_STATUS
( *EFI_BIS_SHUTDOWN)(
BIS_APPLICATION_HANDLE AppHandle
);
typedef
EFI_STATUS
( *EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_CERTIFICATE)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA **Certificate
);
typedef
EFI_STATUS
( *EFI_BIS_VERIFY_BOOT_OBJECT)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA *Credentials,
EFI_BIS_DATA *DataObject,
BOOLEAN *IsVerified
);
typedef
EFI_STATUS
( *EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_CHECKFLAG)(
BIS_APPLICATION_HANDLE AppHandle,
BOOLEAN *CheckIsRequired
);
typedef
EFI_STATUS
( *EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_UPDATE_TOKEN)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA **UpdateToken
);
typedef
EFI_STATUS
( *EFI_BIS_UPDATE_BOOT_OBJECT_AUTHORIZATION)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA *RequestCredential,
EFI_BIS_DATA **NewUpdateToken
);
typedef
EFI_STATUS
( *EFI_BIS_VERIFY_OBJECT_WITH_CREDENTIAL)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA *Credentials,
EFI_BIS_DATA *DataObject,
EFI_BIS_DATA *SectionName,
EFI_BIS_DATA *AuthorityCertificate,
BOOLEAN *IsVerified
);
typedef
EFI_STATUS
( *EFI_BIS_GET_SIGNATURE_INFO)(
BIS_APPLICATION_HANDLE AppHandle,
EFI_BIS_DATA **SignatureInfo
);

struct _EFI_BIS_PROTOCOL {
EFI_BIS_INITIALIZE Initialize;
EFI_BIS_SHUTDOWN Shutdown;
EFI_BIS_FREE Free;
EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_CERTIFICATE GetBootObjectAuthorizationCertificate;
EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_CHECKFLAG GetBootObjectAuthorizationCheckFlag;
EFI_BIS_GET_BOOT_OBJECT_AUTHORIZATION_UPDATE_TOKEN GetBootObjectAuthorizationUpdateToken;
EFI_BIS_GET_SIGNATURE_INFO GetSignatureInfo;
EFI_BIS_UPDATE_BOOT_OBJECT_AUTHORIZATION UpdateBootObjectAuthorization;
EFI_BIS_VERIFY_BOOT_OBJECT VerifyBootObject;
EFI_BIS_VERIFY_OBJECT_WITH_CREDENTIAL VerifyObjectWithCredential;
};

extern EFI_GUID gEfiBisProtocolGuid;
extern EFI_GUID gBootObjectAuthorizationParmsetGuid;
typedef struct _EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;
typedef EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO;
typedef
EFI_STATUS
( *EFI_BLOCK_RESET)(
EFI_BLOCK_IO_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_BLOCK_READ)(
EFI_BLOCK_IO_PROTOCOL *This,
UINT32 MediaId,
EFI_LBA Lba,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_BLOCK_WRITE)(
EFI_BLOCK_IO_PROTOCOL *This,
UINT32 MediaId,
EFI_LBA Lba,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_BLOCK_FLUSH)(
EFI_BLOCK_IO_PROTOCOL *This
);

typedef struct {

UINT32 MediaId;

BOOLEAN RemovableMedia;

BOOLEAN MediaPresent;

BOOLEAN LogicalPartition;

BOOLEAN ReadOnly;

BOOLEAN WriteCaching;

UINT32 BlockSize;

UINT32 IoAlign;

EFI_LBA LastBlock;

EFI_LBA LowestAlignedLba;

UINT32 LogicalBlocksPerPhysicalBlock;

UINT32 OptimalTransferLengthGranularity;
} EFI_BLOCK_IO_MEDIA;
struct _EFI_BLOCK_IO_PROTOCOL {

UINT64 Revision;

EFI_BLOCK_IO_MEDIA *Media;

EFI_BLOCK_RESET Reset;
EFI_BLOCK_READ ReadBlocks;
EFI_BLOCK_WRITE WriteBlocks;
EFI_BLOCK_FLUSH FlushBlocks;

};

extern EFI_GUID gEfiBlockIoProtocolGuid;
typedef struct _EFI_BLOCK_IO2_PROTOCOL EFI_BLOCK_IO2_PROTOCOL;

typedef struct {

EFI_EVENT Event;

EFI_STATUS TransactionStatus;
} EFI_BLOCK_IO2_TOKEN;
typedef
EFI_STATUS
( *EFI_BLOCK_RESET_EX) (
EFI_BLOCK_IO2_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_BLOCK_READ_EX) (
EFI_BLOCK_IO2_PROTOCOL *This,
UINT32 MediaId,
EFI_LBA LBA,
EFI_BLOCK_IO2_TOKEN *Token,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_BLOCK_WRITE_EX) (
EFI_BLOCK_IO2_PROTOCOL *This,
UINT32 MediaId,
EFI_LBA LBA,
EFI_BLOCK_IO2_TOKEN *Token,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_BLOCK_FLUSH_EX) (
EFI_BLOCK_IO2_PROTOCOL *This,
EFI_BLOCK_IO2_TOKEN *Token
);

struct _EFI_BLOCK_IO2_PROTOCOL {

EFI_BLOCK_IO_MEDIA *Media;

EFI_BLOCK_RESET_EX Reset;
EFI_BLOCK_READ_EX ReadBlocksEx;
EFI_BLOCK_WRITE_EX WriteBlocksEx;
EFI_BLOCK_FLUSH_EX FlushBlocksEx;
};

extern EFI_GUID gEfiBlockIo2ProtocolGuid;
typedef struct _EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_GET_DRIVER)(
EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL *This,
EFI_HANDLE *DriverImageHandle
);

struct _EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL {
EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_GET_DRIVER GetDriver;
};

extern EFI_GUID gEfiBusSpecificDriverOverrideProtocolGuid;
extern EFI_GUID gEfiCapsuleArchProtocolGuid;

typedef struct _EFI_CPU_ARCH_PROTOCOL EFI_CPU_ARCH_PROTOCOL;

typedef enum {
EfiCpuFlushTypeWriteBackInvalidate,
EfiCpuFlushTypeWriteBack,
EfiCpuFlushTypeInvalidate,
EfiCpuMaxFlushType
} EFI_CPU_FLUSH_TYPE;

typedef enum {
EfiCpuInit,
EfiCpuMaxInitType
} EFI_CPU_INIT_TYPE;
typedef
void
( *EFI_CPU_INTERRUPT_HANDLER)(
EFI_EXCEPTION_TYPE InterruptType,
EFI_SYSTEM_CONTEXT SystemContext
);
typedef
EFI_STATUS
( *EFI_CPU_FLUSH_DATA_CACHE)(
EFI_CPU_ARCH_PROTOCOL *This,
EFI_PHYSICAL_ADDRESS Start,
UINT64 Length,
EFI_CPU_FLUSH_TYPE FlushType
);
typedef
EFI_STATUS
( *EFI_CPU_ENABLE_INTERRUPT)(
EFI_CPU_ARCH_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_CPU_DISABLE_INTERRUPT)(
EFI_CPU_ARCH_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_CPU_GET_INTERRUPT_STATE)(
EFI_CPU_ARCH_PROTOCOL *This,
BOOLEAN *State
);
typedef
EFI_STATUS
( *EFI_CPU_INIT)(
EFI_CPU_ARCH_PROTOCOL *This,
EFI_CPU_INIT_TYPE InitType
);
typedef
EFI_STATUS
( *EFI_CPU_REGISTER_INTERRUPT_HANDLER)(
EFI_CPU_ARCH_PROTOCOL *This,
EFI_EXCEPTION_TYPE InterruptType,
EFI_CPU_INTERRUPT_HANDLER InterruptHandler
);
typedef
EFI_STATUS
( *EFI_CPU_GET_TIMER_VALUE)(
EFI_CPU_ARCH_PROTOCOL *This,
UINT32 TimerIndex,
UINT64 *TimerValue,
UINT64 *TimerPeriod
);
typedef
EFI_STATUS
( *EFI_CPU_SET_MEMORY_ATTRIBUTES)(
EFI_CPU_ARCH_PROTOCOL *This,
EFI_PHYSICAL_ADDRESS BaseAddress,
UINT64 Length,
UINT64 Attributes
);
struct _EFI_CPU_ARCH_PROTOCOL {
EFI_CPU_FLUSH_DATA_CACHE FlushDataCache;
EFI_CPU_ENABLE_INTERRUPT EnableInterrupt;
EFI_CPU_DISABLE_INTERRUPT DisableInterrupt;
EFI_CPU_GET_INTERRUPT_STATE GetInterruptState;
EFI_CPU_INIT Init;
EFI_CPU_REGISTER_INTERRUPT_HANDLER RegisterInterruptHandler;
EFI_CPU_GET_TIMER_VALUE GetTimerValue;
EFI_CPU_SET_MEMORY_ATTRIBUTES SetMemoryAttributes;

UINT32 NumberOfTimers;

UINT32 DmaBufferAlignment;
};

extern EFI_GUID gEfiCpuArchProtocolGuid;
typedef struct _EFI_CPU_IO2_PROTOCOL EFI_CPU_IO2_PROTOCOL;

typedef enum {
EfiCpuIoWidthUint8,
EfiCpuIoWidthUint16,
EfiCpuIoWidthUint32,
EfiCpuIoWidthUint64,
EfiCpuIoWidthFifoUint8,
EfiCpuIoWidthFifoUint16,
EfiCpuIoWidthFifoUint32,
EfiCpuIoWidthFifoUint64,
EfiCpuIoWidthFillUint8,
EfiCpuIoWidthFillUint16,
EfiCpuIoWidthFillUint32,
EfiCpuIoWidthFillUint64,
EfiCpuIoWidthMaximum
} EFI_CPU_IO_PROTOCOL_WIDTH;
typedef
EFI_STATUS
( *EFI_CPU_IO_PROTOCOL_IO_MEM)(
EFI_CPU_IO2_PROTOCOL *This,
EFI_CPU_IO_PROTOCOL_WIDTH Width,
UINT64 Address,
UINTN Count,
void *Buffer
);

typedef struct {

EFI_CPU_IO_PROTOCOL_IO_MEM Read;

EFI_CPU_IO_PROTOCOL_IO_MEM Write;
} EFI_CPU_IO_PROTOCOL_ACCESS;

struct _EFI_CPU_IO2_PROTOCOL {

EFI_CPU_IO_PROTOCOL_ACCESS Mem;

EFI_CPU_IO_PROTOCOL_ACCESS Io;
};

extern EFI_GUID gEfiCpuIo2ProtocolGuid;
extern EFI_GUID gEfiDebugPortProtocolGuid;

typedef struct _EFI_DEBUGPORT_PROTOCOL EFI_DEBUGPORT_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DEBUGPORT_RESET)(
EFI_DEBUGPORT_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_DEBUGPORT_WRITE)(
EFI_DEBUGPORT_PROTOCOL *This,
UINT32 Timeout,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_DEBUGPORT_READ)(
EFI_DEBUGPORT_PROTOCOL *This,
UINT32 Timeout,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_DEBUGPORT_POLL)(
EFI_DEBUGPORT_PROTOCOL *This
);

struct _EFI_DEBUGPORT_PROTOCOL {
EFI_DEBUGPORT_RESET Reset;
EFI_DEBUGPORT_WRITE Write;
EFI_DEBUGPORT_READ Read;
EFI_DEBUGPORT_POLL Poll;
};
typedef struct {
EFI_DEVICE_PATH_PROTOCOL Header;
EFI_GUID Guid;
} DEBUGPORT_DEVICE_PATH;

typedef struct _EFI_DECOMPRESS_PROTOCOL EFI_DECOMPRESS_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DECOMPRESS_GET_INFO)(
EFI_DECOMPRESS_PROTOCOL *This,
void *Source,
UINT32 SourceSize,
UINT32 *DestinationSize,
UINT32 *ScratchSize
);
typedef
EFI_STATUS
( *EFI_DECOMPRESS_DECOMPRESS)(
EFI_DECOMPRESS_PROTOCOL *This,
void *Source,
UINT32 SourceSize,
void *Destination,
UINT32 DestinationSize,
void *Scratch,
UINT32 ScratchSize
);

struct _EFI_DECOMPRESS_PROTOCOL {
EFI_DECOMPRESS_GET_INFO GetInfo;
EFI_DECOMPRESS_DECOMPRESS Decompress;
};

extern EFI_GUID gEfiDecompressProtocolGuid;
typedef struct _EFI_DEFERRED_IMAGE_LOAD_PROTOCOL EFI_DEFERRED_IMAGE_LOAD_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DEFERRED_IMAGE_INFO)(
EFI_DEFERRED_IMAGE_LOAD_PROTOCOL *This,
UINTN ImageIndex,
EFI_DEVICE_PATH_PROTOCOL **ImageDevicePath,
void **Image,
UINTN *ImageSize,
BOOLEAN *BootOption
);

struct _EFI_DEFERRED_IMAGE_LOAD_PROTOCOL {
EFI_DEFERRED_IMAGE_INFO GetImageInfo;
};

extern EFI_GUID gEfiDeferredImageLoadProtocolGuid;
typedef struct _EFI_DEVICE_IO_PROTOCOL EFI_DEVICE_IO_PROTOCOL;
typedef EFI_DEVICE_IO_PROTOCOL EFI_DEVICE_IO_INTERFACE;

typedef enum {
IO_UINT8 = 0,
IO_UINT16 = 1,
IO_UINT32 = 2,
IO_UINT64 = 3,

MMIO_COPY_UINT8 = 4,
MMIO_COPY_UINT16 = 5,
MMIO_COPY_UINT32 = 6,
MMIO_COPY_UINT64 = 7
} EFI_IO_WIDTH;
typedef
EFI_STATUS
( *EFI_DEVICE_IO)(
EFI_DEVICE_IO_PROTOCOL *This,
EFI_IO_WIDTH Width,
UINT64 Address,
UINTN Count,
void *Buffer
);

typedef struct {
EFI_DEVICE_IO Read;
EFI_DEVICE_IO Write;
} EFI_IO_ACCESS;
typedef
EFI_STATUS
( *EFI_PCI_DEVICE_PATH)(
EFI_DEVICE_IO_PROTOCOL *This,
UINT64 PciAddress,
EFI_DEVICE_PATH_PROTOCOL **PciDevicePath
);

typedef enum {

EfiBusMasterRead,

EfiBusMasterWrite,

EfiBusMasterCommonBuffer
} EFI_IO_OPERATION_TYPE;
typedef
EFI_STATUS
( *EFI_IO_MAP)(
EFI_DEVICE_IO_PROTOCOL *This,
EFI_IO_OPERATION_TYPE Operation,
EFI_PHYSICAL_ADDRESS *HostAddress,
UINTN *NumberOfBytes,
EFI_PHYSICAL_ADDRESS *DeviceAddress,
void **Mapping
);
typedef
EFI_STATUS
( *EFI_IO_UNMAP)(
EFI_DEVICE_IO_PROTOCOL *This,
void *Mapping
);
typedef
EFI_STATUS
( *EFI_IO_ALLOCATE_BUFFER)(
EFI_DEVICE_IO_PROTOCOL *This,
EFI_ALLOCATE_TYPE Type,
EFI_MEMORY_TYPE MemoryType,
UINTN Pages,
EFI_PHYSICAL_ADDRESS *HostAddress
);
typedef
EFI_STATUS
( *EFI_IO_FLUSH)(
EFI_DEVICE_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_IO_FREE_BUFFER)(
EFI_DEVICE_IO_PROTOCOL *This,
UINTN Pages,
EFI_PHYSICAL_ADDRESS HostAddress
);

struct _EFI_DEVICE_IO_PROTOCOL {

EFI_IO_ACCESS Mem;

EFI_IO_ACCESS Io;

EFI_IO_ACCESS Pci;
EFI_IO_MAP Map;
EFI_PCI_DEVICE_PATH PciDevicePath;
EFI_IO_UNMAP Unmap;
EFI_IO_ALLOCATE_BUFFER AllocateBuffer;
EFI_IO_FLUSH Flush;
EFI_IO_FREE_BUFFER FreeBuffer;
};

extern EFI_GUID gEfiDeviceIoProtocolGuid;

typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_FROM_TEXT_NODE)(
CHAR16 *TextDeviceNode
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_FROM_TEXT_PATH)(
CHAR16 *TextDevicePath
);

typedef struct {
EFI_DEVICE_PATH_FROM_TEXT_NODE ConvertTextToDeviceNode;
EFI_DEVICE_PATH_FROM_TEXT_PATH ConvertTextToDevicePath;
} EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL;

extern EFI_GUID gEfiDevicePathFromTextProtocolGuid;
typedef
CHAR16*
( *EFI_DEVICE_PATH_TO_TEXT_NODE)(
EFI_DEVICE_PATH_PROTOCOL *DeviceNode,
BOOLEAN DisplayOnly,
BOOLEAN AllowShortcuts
);
typedef
CHAR16*
( *EFI_DEVICE_PATH_TO_TEXT_PATH)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
BOOLEAN DisplayOnly,
BOOLEAN AllowShortcuts
);

typedef struct {
EFI_DEVICE_PATH_TO_TEXT_NODE ConvertDeviceNodeToText;
EFI_DEVICE_PATH_TO_TEXT_PATH ConvertDevicePathToText;
} EFI_DEVICE_PATH_TO_TEXT_PROTOCOL;

extern EFI_GUID gEfiDevicePathToTextProtocolGuid;
typedef
UINTN
( *EFI_DEVICE_PATH_UTILS_GET_DEVICE_PATH_SIZE)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_DUP_DEVICE_PATH)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_APPEND_PATH)(
EFI_DEVICE_PATH_PROTOCOL *Src1,
EFI_DEVICE_PATH_PROTOCOL *Src2
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_APPEND_NODE)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
EFI_DEVICE_PATH_PROTOCOL *DeviceNode
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_APPEND_INSTANCE)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
EFI_DEVICE_PATH_PROTOCOL *DevicePathInstance
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_GET_NEXT_INSTANCE)(
EFI_DEVICE_PATH_PROTOCOL **DevicePathInstance,
UINTN *DevicePathInstanceSize
);
typedef
EFI_DEVICE_PATH_PROTOCOL*
( *EFI_DEVICE_PATH_UTILS_CREATE_NODE)(
UINT8 NodeType,
UINT8 NodeSubType,
UINT16 NodeLength
);
typedef
BOOLEAN
( *EFI_DEVICE_PATH_UTILS_IS_MULTI_INSTANCE)(
EFI_DEVICE_PATH_PROTOCOL *DevicePath
);

typedef struct {
EFI_DEVICE_PATH_UTILS_GET_DEVICE_PATH_SIZE GetDevicePathSize;
EFI_DEVICE_PATH_UTILS_DUP_DEVICE_PATH DuplicateDevicePath;
EFI_DEVICE_PATH_UTILS_APPEND_PATH AppendDevicePath;
EFI_DEVICE_PATH_UTILS_APPEND_NODE AppendDeviceNode;
EFI_DEVICE_PATH_UTILS_APPEND_INSTANCE AppendDevicePathInstance;
EFI_DEVICE_PATH_UTILS_GET_NEXT_INSTANCE GetNextDevicePathInstance;
EFI_DEVICE_PATH_UTILS_IS_MULTI_INSTANCE IsDevicePathMultiInstance;
EFI_DEVICE_PATH_UTILS_CREATE_NODE CreateDeviceNode;
} EFI_DEVICE_PATH_UTILITIES_PROTOCOL;

extern EFI_GUID gEfiDevicePathUtilitiesProtocolGuid;
typedef struct _EFI_DHCP4_PROTOCOL EFI_DHCP4_PROTOCOL;

#pragma pack(1)
typedef struct {

UINT8 OpCode;

UINT8 Length;

UINT8 Data[1];
} EFI_DHCP4_PACKET_OPTION;
#pragma pack()

#pragma pack(1)

typedef struct {
UINT8 OpCode;
UINT8 HwType;
UINT8 HwAddrLen;
UINT8 Hops;
UINT32 Xid;
UINT16 Seconds;
UINT16 Reserved;
EFI_IPv4_ADDRESS ClientAddr;
EFI_IPv4_ADDRESS YourAddr;
EFI_IPv4_ADDRESS ServerAddr;
EFI_IPv4_ADDRESS GatewayAddr;
UINT8 ClientHwAddr[16];
CHAR8 ServerName[64];
CHAR8 BootFileName[128];
}EFI_DHCP4_HEADER;
#pragma pack()

#pragma pack(1)
typedef struct {

UINT32 Size;

UINT32 Length;

struct {

EFI_DHCP4_HEADER Header;

UINT32 Magik;

UINT8 Option[1];
} Dhcp4;
} EFI_DHCP4_PACKET;
#pragma pack()

typedef enum {

Dhcp4Stopped = 0x0,

Dhcp4Init = 0x1,

Dhcp4Selecting = 0x2,

Dhcp4Requesting = 0x3,

Dhcp4Bound = 0x4,

Dhcp4Renewing = 0x5,

Dhcp4Rebinding = 0x6,

Dhcp4InitReboot = 0x7,

Dhcp4Rebooting = 0x8
} EFI_DHCP4_STATE;

typedef enum{

Dhcp4SendDiscover = 0x01,

Dhcp4RcvdOffer = 0x02,

Dhcp4SelectOffer = 0x03,

Dhcp4SendRequest = 0x04,

Dhcp4RcvdAck = 0x05,

Dhcp4RcvdNak = 0x06,

Dhcp4SendDecline = 0x07,

Dhcp4BoundCompleted = 0x08,

Dhcp4EnterRenewing = 0x09,

Dhcp4EnterRebinding = 0x0a,

Dhcp4AddressLost = 0x0b,

Dhcp4Fail = 0x0c
} EFI_DHCP4_EVENT;
typedef
EFI_STATUS
( *EFI_DHCP4_CALLBACK)(
EFI_DHCP4_PROTOCOL *This,
void *Context,
EFI_DHCP4_STATE CurrentState,
EFI_DHCP4_EVENT Dhcp4Event,
EFI_DHCP4_PACKET *Packet ,
EFI_DHCP4_PACKET **NewPacket
);

typedef struct {

UINT32 DiscoverTryCount;

UINT32 *DiscoverTimeout;

UINT32 RequestTryCount;

UINT32 *RequestTimeout;

EFI_IPv4_ADDRESS ClientAddress;

EFI_DHCP4_CALLBACK Dhcp4Callback;

void *CallbackContext;

UINT32 OptionCount;

EFI_DHCP4_PACKET_OPTION **OptionList;
} EFI_DHCP4_CONFIG_DATA;

typedef struct {

EFI_DHCP4_STATE State;

EFI_DHCP4_CONFIG_DATA ConfigData;

EFI_IPv4_ADDRESS ClientAddress;

EFI_MAC_ADDRESS ClientMacAddress;

EFI_IPv4_ADDRESS ServerAddress;

EFI_IPv4_ADDRESS RouterAddress;

EFI_IPv4_ADDRESS SubnetMask;

UINT32 LeaseTime;

EFI_DHCP4_PACKET *ReplyPacket;
} EFI_DHCP4_MODE_DATA;

typedef struct {

EFI_IPv4_ADDRESS ListenAddress;

EFI_IPv4_ADDRESS SubnetMask;

UINT16 ListenPort;
} EFI_DHCP4_LISTEN_POINT;

typedef struct {

EFI_STATUS Status;

EFI_EVENT CompletionEvent;

EFI_IPv4_ADDRESS RemoteAddress;

UINT16 RemotePort;

EFI_IPv4_ADDRESS GatewayAddress;

UINT32 ListenPointCount;

EFI_DHCP4_LISTEN_POINT *ListenPoints;

UINT32 TimeoutValue;

EFI_DHCP4_PACKET *Packet;

UINT32 ResponseCount;

EFI_DHCP4_PACKET *ResponseList;
} EFI_DHCP4_TRANSMIT_RECEIVE_TOKEN;
typedef
EFI_STATUS
( *EFI_DHCP4_GET_MODE_DATA)(
EFI_DHCP4_PROTOCOL *This,
EFI_DHCP4_MODE_DATA *Dhcp4ModeData
);
typedef
EFI_STATUS
( *EFI_DHCP4_CONFIGURE)(
EFI_DHCP4_PROTOCOL *This,
EFI_DHCP4_CONFIG_DATA *Dhcp4CfgData
);
typedef
EFI_STATUS
( *EFI_DHCP4_START)(
EFI_DHCP4_PROTOCOL *This,
EFI_EVENT CompletionEvent
);
typedef
EFI_STATUS
( *EFI_DHCP4_RENEW_REBIND)(
EFI_DHCP4_PROTOCOL *This,
BOOLEAN RebindRequest,
EFI_EVENT CompletionEvent
);
typedef
EFI_STATUS
( *EFI_DHCP4_RELEASE)(
EFI_DHCP4_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_DHCP4_STOP)(
EFI_DHCP4_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_DHCP4_BUILD)(
EFI_DHCP4_PROTOCOL *This,
EFI_DHCP4_PACKET *SeedPacket,
UINT32 DeleteCount,
UINT8 *DeleteList ,
UINT32 AppendCount,
EFI_DHCP4_PACKET_OPTION *AppendList[] ,
EFI_DHCP4_PACKET **NewPacket
);
typedef
EFI_STATUS
( *EFI_DHCP4_TRANSMIT_RECEIVE)(
EFI_DHCP4_PROTOCOL *This,
EFI_DHCP4_TRANSMIT_RECEIVE_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_DHCP4_PARSE)(
EFI_DHCP4_PROTOCOL *This,
EFI_DHCP4_PACKET *Packet,
UINT32 *OptionCount,
EFI_DHCP4_PACKET_OPTION *PacketOptionList[]
);

struct _EFI_DHCP4_PROTOCOL {
EFI_DHCP4_GET_MODE_DATA GetModeData;
EFI_DHCP4_CONFIGURE Configure;
EFI_DHCP4_START Start;
EFI_DHCP4_RENEW_REBIND RenewRebind;
EFI_DHCP4_RELEASE Release;
EFI_DHCP4_STOP Stop;
EFI_DHCP4_BUILD Build;
EFI_DHCP4_TRANSMIT_RECEIVE TransmitReceive;
EFI_DHCP4_PARSE Parse;
};

extern EFI_GUID gEfiDhcp4ProtocolGuid;
extern EFI_GUID gEfiDhcp4ServiceBindingProtocolGuid;
typedef struct _EFI_DHCP6_PROTOCOL EFI_DHCP6_PROTOCOL;

typedef enum {

Dhcp6Init = 0x0,

Dhcp6Selecting = 0x1,

Dhcp6Requesting = 0x2,

Dhcp6Declining = 0x3,

Dhcp6Confirming = 0x4,

Dhcp6Releasing = 0x5,

Dhcp6Bound = 0x6,

Dhcp6Renewing = 0x7,

Dhcp6Rebinding = 0x8
} EFI_DHCP6_STATE;

typedef enum {

Dhcp6SendSolicit = 0x0,

Dhcp6RcvdAdvertise = 0x1,

Dhcp6SelectAdvertise = 0x2,

Dhcp6SendRequest = 0x3,

Dhcp6RcvdReply = 0x4,

Dhcp6RcvdReconfigure = 0x5,

Dhcp6SendDecline = 0x6,

Dhcp6SendConfirm = 0x7,

Dhcp6SendRelease = 0x8,

Dhcp6EnterRenewing = 0x9,

Dhcp6EnterRebinding = 0xa
} EFI_DHCP6_EVENT;
#pragma pack(1)

typedef struct {

UINT16 OpCode;

UINT16 OpLen;

UINT8 Data[1];
} EFI_DHCP6_PACKET_OPTION;

typedef struct{

UINT32 MessageType:8;

UINT32 TransactionId:24;
} EFI_DHCP6_HEADER;

typedef struct {

UINT32 Size;

UINT32 Length;
struct{

EFI_DHCP6_HEADER Header;

UINT8 Option[1];
} Dhcp6;
} EFI_DHCP6_PACKET;

#pragma pack()

typedef struct {

UINT16 Length;

UINT8 Duid[1];
} EFI_DHCP6_DUID;

typedef struct {

UINT32 Irt;

UINT32 Mrc;

UINT32 Mrt;

UINT32 Mrd;
} EFI_DHCP6_RETRANSMISSION;

typedef struct {

EFI_IPv6_ADDRESS IpAddress;

UINT32 PreferredLifetime;

UINT32 ValidLifetime;
} EFI_DHCP6_IA_ADDRESS;

typedef struct {
UINT16 Type;
UINT32 IaId;
} EFI_DHCP6_IA_DESCRIPTOR;

typedef struct {

EFI_DHCP6_IA_DESCRIPTOR Descriptor;

EFI_DHCP6_STATE State;

EFI_DHCP6_PACKET *ReplyPacket;

UINT32 IaAddressCount;

EFI_DHCP6_IA_ADDRESS IaAddress[1];
} EFI_DHCP6_IA;

typedef struct {

EFI_DHCP6_DUID *ClientId;

EFI_DHCP6_IA *Ia;
} EFI_DHCP6_MODE_DATA;
typedef
EFI_STATUS
( *EFI_DHCP6_CALLBACK)(
EFI_DHCP6_PROTOCOL *This,
void *Context,
EFI_DHCP6_STATE CurrentState,
EFI_DHCP6_EVENT Dhcp6Event,
EFI_DHCP6_PACKET *Packet,
EFI_DHCP6_PACKET **NewPacket
);

typedef struct {

EFI_DHCP6_CALLBACK Dhcp6Callback;

void *CallbackContext;

UINT32 OptionCount;

EFI_DHCP6_PACKET_OPTION **OptionList;

EFI_DHCP6_IA_DESCRIPTOR IaDescriptor;

EFI_EVENT IaInfoEvent;

BOOLEAN ReconfigureAccept;

BOOLEAN RapidCommit;

EFI_DHCP6_RETRANSMISSION *SolicitRetransmission;
} EFI_DHCP6_CONFIG_DATA;
typedef
EFI_STATUS
( *EFI_DHCP6_INFO_CALLBACK)(
EFI_DHCP6_PROTOCOL *This,
void *Context,
EFI_DHCP6_PACKET *Packet
);
typedef
EFI_STATUS
( *EFI_DHCP6_GET_MODE_DATA)(
EFI_DHCP6_PROTOCOL *This,
EFI_DHCP6_MODE_DATA *Dhcp6ModeData ,
EFI_DHCP6_CONFIG_DATA *Dhcp6ConfigData
);
typedef
EFI_STATUS
( *EFI_DHCP6_CONFIGURE)(
EFI_DHCP6_PROTOCOL *This,
EFI_DHCP6_CONFIG_DATA *Dhcp6CfgData
);
typedef
EFI_STATUS
( *EFI_DHCP6_START)(
EFI_DHCP6_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_DHCP6_INFO_REQUEST)(
EFI_DHCP6_PROTOCOL *This,
BOOLEAN SendClientId,
EFI_DHCP6_PACKET_OPTION *OptionRequest,
UINT32 OptionCount,
EFI_DHCP6_PACKET_OPTION *OptionList[] ,
EFI_DHCP6_RETRANSMISSION *Retransmission,
EFI_EVENT TimeoutEvent ,
EFI_DHCP6_INFO_CALLBACK ReplyCallback,
void *CallbackContext
);
typedef
EFI_STATUS
( *EFI_DHCP6_RENEW_REBIND)(
EFI_DHCP6_PROTOCOL *This,
BOOLEAN RebindRequest
);
typedef
EFI_STATUS
( *EFI_DHCP6_DECLINE)(
EFI_DHCP6_PROTOCOL *This,
UINT32 AddressCount,
EFI_IPv6_ADDRESS *Addresses
);
typedef
EFI_STATUS
( *EFI_DHCP6_RELEASE)(
EFI_DHCP6_PROTOCOL *This,
UINT32 AddressCount,
EFI_IPv6_ADDRESS *Addresses
);
typedef
EFI_STATUS
( *EFI_DHCP6_STOP)(
EFI_DHCP6_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_DHCP6_PARSE)(
EFI_DHCP6_PROTOCOL *This,
EFI_DHCP6_PACKET *Packet,
UINT32 *OptionCount,
EFI_DHCP6_PACKET_OPTION *PacketOptionList[]
);

struct _EFI_DHCP6_PROTOCOL {
EFI_DHCP6_GET_MODE_DATA GetModeData;
EFI_DHCP6_CONFIGURE Configure;
EFI_DHCP6_START Start;
EFI_DHCP6_INFO_REQUEST InfoRequest;
EFI_DHCP6_RENEW_REBIND RenewRebind;
EFI_DHCP6_DECLINE Decline;
EFI_DHCP6_RELEASE Release;
EFI_DHCP6_STOP Stop;
EFI_DHCP6_PARSE Parse;
};

extern EFI_GUID gEfiDhcp6ProtocolGuid;
extern EFI_GUID gEfiDhcp6ServiceBindingProtocolGuid;
typedef struct _EFI_DISK_INFO_PROTOCOL EFI_DISK_INFO_PROTOCOL;
typedef
EFI_STATUS
( *EFI_DISK_INFO_INQUIRY)(
EFI_DISK_INFO_PROTOCOL *This,
void *InquiryData,
UINT32 *InquiryDataSize
);
typedef
EFI_STATUS
( *EFI_DISK_INFO_IDENTIFY)(
EFI_DISK_INFO_PROTOCOL *This,
void *IdentifyData,
UINT32 *IdentifyDataSize
);
typedef
EFI_STATUS
( *EFI_DISK_INFO_SENSE_DATA)(
EFI_DISK_INFO_PROTOCOL *This,
void *SenseData,
UINT32 *SenseDataSize,
UINT8 *SenseDataNumber
);
typedef
EFI_STATUS
( *EFI_DISK_INFO_WHICH_IDE)(
EFI_DISK_INFO_PROTOCOL *This,
UINT32 *IdeChannel,
UINT32 *IdeDevice
);

struct _EFI_DISK_INFO_PROTOCOL {

EFI_GUID Interface;

EFI_DISK_INFO_INQUIRY Inquiry;

EFI_DISK_INFO_IDENTIFY Identify;

EFI_DISK_INFO_SENSE_DATA SenseData;

EFI_DISK_INFO_WHICH_IDE WhichIde;
};

extern EFI_GUID gEfiDiskInfoProtocolGuid;

extern EFI_GUID gEfiDiskInfoIdeInterfaceGuid;
extern EFI_GUID gEfiDiskInfoScsiInterfaceGuid;
extern EFI_GUID gEfiDiskInfoUsbInterfaceGuid;
extern EFI_GUID gEfiDiskInfoAhciInterfaceGuid;
typedef struct _EFI_DISK_IO_PROTOCOL EFI_DISK_IO_PROTOCOL;

typedef EFI_DISK_IO_PROTOCOL EFI_DISK_IO;
typedef
EFI_STATUS
( *EFI_DISK_READ)(
EFI_DISK_IO_PROTOCOL *This,
UINT32 MediaId,
UINT64 Offset,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_DISK_WRITE)(
EFI_DISK_IO_PROTOCOL *This,
UINT32 MediaId,
UINT64 Offset,
UINTN BufferSize,
void *Buffer
);
struct _EFI_DISK_IO_PROTOCOL {

UINT64 Revision;
EFI_DISK_READ ReadDisk;
EFI_DISK_WRITE WriteDisk;
};

extern EFI_GUID gEfiDiskIoProtocolGuid;

typedef struct _EFI_DRIVER_FAMILY_OVERRIDE_PROTOCOL EFI_DRIVER_FAMILY_OVERRIDE_PROTOCOL;
typedef
UINT32
( *EFI_DRIVER_FAMILY_OVERRIDE_GET_VERSION)(
EFI_DRIVER_FAMILY_OVERRIDE_PROTOCOL *This
);
struct _EFI_DRIVER_FAMILY_OVERRIDE_PROTOCOL {
EFI_DRIVER_FAMILY_OVERRIDE_GET_VERSION GetVersion;
};

extern EFI_GUID gEfiDriverFamilyOverrideProtocolGuid;
typedef struct _EFI_DRIVER_HEALTH_PROTOCOL EFI_DRIVER_HEALTH_PROTOCOL;

typedef enum {
EfiDriverHealthStatusHealthy,
EfiDriverHealthStatusRepairRequired,
EfiDriverHealthStatusConfigurationRequired,
EfiDriverHealthStatusFailed,
EfiDriverHealthStatusReconnectRequired,
EfiDriverHealthStatusRebootRequired
} EFI_DRIVER_HEALTH_STATUS;

typedef struct {
EFI_HII_HANDLE HiiHandle;
EFI_STRING_ID StringId;
UINT64 Reserved;
} EFI_DRIVER_HEALTH_HII_MESSAGE;
typedef
EFI_STATUS
( *EFI_DRIVER_HEALTH_REPAIR_PROGRESS_NOTIFY)(
UINTN Value,
UINTN Limit
);
typedef
EFI_STATUS
( *EFI_DRIVER_HEALTH_GET_HEALTH_STATUS)(
EFI_DRIVER_HEALTH_PROTOCOL *This,
EFI_HANDLE ControllerHandle ,
EFI_HANDLE ChildHandle ,
EFI_DRIVER_HEALTH_STATUS *HealthStatus,
EFI_DRIVER_HEALTH_HII_MESSAGE **MessageList ,
EFI_HII_HANDLE *FormHiiHandle
);
typedef
EFI_STATUS
( *EFI_DRIVER_HEALTH_REPAIR)(
EFI_DRIVER_HEALTH_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
EFI_DRIVER_HEALTH_REPAIR_PROGRESS_NOTIFY ProgressNotification
);
struct _EFI_DRIVER_HEALTH_PROTOCOL {
EFI_DRIVER_HEALTH_GET_HEALTH_STATUS GetHealthStatus;
EFI_DRIVER_HEALTH_REPAIR Repair;
};

extern EFI_GUID gEfiDriverHealthProtocolGuid;
typedef struct _EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL {

UINT32 Length;

UINT32 FirmwareVersion;
} EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL;

extern EFI_GUID gEfiDriverSupportedEfiVersionProtocolGuid;
extern EFI_GUID gEfiDxeSmmReadyToLockProtocolGuid;
typedef struct _EFI_EAP_PROTOCOL EFI_EAP_PROTOCOL;

typedef void * EFI_PORT_HANDLE;
typedef
EFI_STATUS
( *EFI_EAP_BUILD_RESPONSE_PACKET)(
EFI_PORT_HANDLE PortNumber,
UINT8 *RequestBuffer,
UINTN RequestSize,
UINT8 *Buffer,
UINTN *BufferSize
);
typedef
EFI_STATUS
( *EFI_EAP_SET_DESIRED_AUTHENTICATION_METHOD)(
EFI_EAP_PROTOCOL *This,
UINT8 EapAuthType
);
typedef
EFI_STATUS
( *EFI_EAP_REGISTER_AUTHENTICATION_METHOD)(
EFI_EAP_PROTOCOL *This,
UINT8 EapAuthType,
EFI_EAP_BUILD_RESPONSE_PACKET Handler
);
struct _EFI_EAP_PROTOCOL {
EFI_EAP_SET_DESIRED_AUTHENTICATION_METHOD SetDesiredAuthMethod;
EFI_EAP_REGISTER_AUTHENTICATION_METHOD RegisterAuthMethod;
};

extern EFI_GUID gEfiEapProtocolGuid;
typedef struct _EFI_EAP_MANAGEMENT_PROTOCOL EFI_EAP_MANAGEMENT_PROTOCOL;
typedef struct _EFI_EAPOL_PORT_INFO {

EFI_PORT_HANDLE PortNumber;

UINT8 ProtocolVersion;

UINT8 PaeCapabilities;
} EFI_EAPOL_PORT_INFO;

typedef enum _EFI_EAPOL_SUPPLICANT_PAE_STATE {
Logoff,
Disconnected,
Connecting,
Acquired,
Authenticating,
Held,
Authenticated,
MaxSupplicantPaeState
} EFI_EAPOL_SUPPLICANT_PAE_STATE;
typedef struct _EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION {

UINT8 ValidFieldMask;

UINTN AuthPeriod;

UINTN HeldPeriod;

UINTN StartPeriod;

UINTN MaxStart;
} EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION;

typedef struct _EFI_EAPOL_SUPPLICANT_PAE_STATISTICS {

UINTN EapolFramesReceived;

UINTN EapolFramesTransmitted;

UINTN EapolStartFramesTransmitted;

UINTN EapolLogoffFramesTransmitted;

UINTN EapRespIdFramesTransmitted;

UINTN EapResponseFramesTransmitted;

UINTN EapReqIdFramesReceived;

UINTN EapRequestFramesReceived;

UINTN InvalidEapolFramesReceived;

UINTN EapLengthErrorFramesReceived;

UINTN LastEapolFrameVersion;

UINTN LastEapolFrameSource;
} EFI_EAPOL_SUPPLICANT_PAE_STATISTICS;
typedef
EFI_STATUS
( *EFI_EAP_GET_SYSTEM_CONFIGURATION)(
EFI_EAP_MANAGEMENT_PROTOCOL *This,
BOOLEAN *SystemAuthControl,
EFI_EAPOL_PORT_INFO *PortInfo
);
typedef
EFI_STATUS
( *EFI_EAP_SET_SYSTEM_CONFIGURATION)(
EFI_EAP_MANAGEMENT_PROTOCOL *This,
BOOLEAN SystemAuthControl
);
typedef
EFI_STATUS
( *EFI_EAP_INITIALIZE_PORT)(
EFI_EAP_MANAGEMENT_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_EAP_USER_LOGON)(
EFI_EAP_MANAGEMENT_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_EAP_USER_LOGOFF)(
EFI_EAP_MANAGEMENT_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_EAP_GET_SUPPLICANT_STATUS)(
EFI_EAP_MANAGEMENT_PROTOCOL *This,
EFI_EAPOL_SUPPLICANT_PAE_STATE *CurrentState,
EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION *Configuration
);
typedef
EFI_STATUS
( *EFI_EAP_SET_SUPPLICANT_CONFIGURATION)(
EFI_EAP_MANAGEMENT_PROTOCOL *This,
EFI_EAPOL_SUPPLICANT_PAE_CONFIGURATION *Configuration
);
typedef
EFI_STATUS
( *EFI_EAP_GET_SUPPLICANT_STATISTICS)(
EFI_EAP_MANAGEMENT_PROTOCOL *This,
EFI_EAPOL_SUPPLICANT_PAE_STATISTICS *Statistics
);
struct _EFI_EAP_MANAGEMENT_PROTOCOL {
EFI_EAP_GET_SYSTEM_CONFIGURATION GetSystemConfiguration;
EFI_EAP_SET_SYSTEM_CONFIGURATION SetSystemConfiguration;
EFI_EAP_INITIALIZE_PORT InitializePort;
EFI_EAP_USER_LOGON UserLogon;
EFI_EAP_USER_LOGOFF UserLogoff;
EFI_EAP_GET_SUPPLICANT_STATUS GetSupplicantStatus;
EFI_EAP_SET_SUPPLICANT_CONFIGURATION SetSupplicantConfiguration;
EFI_EAP_GET_SUPPLICANT_STATISTICS GetSupplicantStatistics;
};

extern EFI_GUID gEfiEapManagementProtocolGuid;
typedef struct _EFI_EBC_PROTOCOL EFI_EBC_PROTOCOL;
typedef
EFI_STATUS
( *EFI_EBC_CREATE_THUNK)(
EFI_EBC_PROTOCOL *This,
EFI_HANDLE ImageHandle,
void *EbcEntryPoint,
void **Thunk
);
typedef
EFI_STATUS
( *EFI_EBC_UNLOAD_IMAGE)(
EFI_EBC_PROTOCOL *This,
EFI_HANDLE ImageHandle
);
typedef
EFI_STATUS
( *EBC_ICACHE_FLUSH)(
EFI_PHYSICAL_ADDRESS Start,
UINT64 Length
);
typedef
EFI_STATUS
( *EFI_EBC_REGISTER_ICACHE_FLUSH)(
EFI_EBC_PROTOCOL *This,
EBC_ICACHE_FLUSH Flush
);
typedef
EFI_STATUS
( *EFI_EBC_GET_VERSION)(
EFI_EBC_PROTOCOL *This,
UINT64 *Version
);

struct _EFI_EBC_PROTOCOL {
EFI_EBC_CREATE_THUNK CreateThunk;
EFI_EBC_UNLOAD_IMAGE UnloadImage;
EFI_EBC_REGISTER_ICACHE_FLUSH RegisterICacheFlush;
EFI_EBC_GET_VERSION GetVersion;
};

extern EFI_GUID gEfiEbcProtocolGuid;
typedef struct {

UINT32 SizeOfEdid;
UINT8 *Edid;
} EFI_EDID_ACTIVE_PROTOCOL;

extern EFI_GUID gEfiEdidActiveProtocolGuid;
typedef struct {

UINT32 SizeOfEdid;
UINT8 *Edid;
} EFI_EDID_DISCOVERED_PROTOCOL;

extern EFI_GUID gEfiEdidDiscoveredProtocolGuid;
typedef struct _EFI_EDID_OVERRIDE_PROTOCOL EFI_EDID_OVERRIDE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_EDID_OVERRIDE_PROTOCOL_GET_EDID)(
EFI_EDID_OVERRIDE_PROTOCOL *This,
EFI_HANDLE *ChildHandle,
UINT32 *Attributes,
UINTN *EdidSize,
UINT8 **Edid
);

struct _EFI_EDID_OVERRIDE_PROTOCOL {
EFI_EDID_OVERRIDE_PROTOCOL_GET_EDID GetEdid;
};

extern EFI_GUID gEfiEdidOverrideProtocolGuid;
typedef INTN EFI_SAL_STATUS;
typedef struct {

EFI_SAL_STATUS Status;

UINTN r9;

UINTN r10;

UINTN r11;
} SAL_RETURN_REGS;
typedef
SAL_RETURN_REGS
( *SAL_PROC)(
UINT64 FunctionId,
UINT64 Arg1,
UINT64 Arg2,
UINT64 Arg3,
UINT64 Arg4,
UINT64 Arg5,
UINT64 Arg6,
UINT64 Arg7
);
typedef struct {
UINT64 Length : 32;
UINT64 ChecksumValid : 1;
UINT64 Reserved1 : 7;
UINT64 ByteChecksum : 8;
UINT64 Reserved2 : 16;
} SAL_SET_VECTORS_CS_N;
typedef struct {
UINT64 Register : 8;
UINT64 Function : 3;
UINT64 Device : 5;
UINT64 Bus : 8;
UINT64 Segment : 8;
UINT64 Reserved : 32;
} SAL_PCI_ADDRESS;

typedef struct {
UINT64 Register : 8;
UINT64 ExtendedRegister : 4;
UINT64 Function : 3;
UINT64 Device : 5;
UINT64 Bus : 8;
UINT64 Segment : 16;
UINT64 Reserved : 20;
} SAL_PCI_EXTENDED_REGISTER_ADDRESS;
typedef struct {
UINT32 Size;
UINT32 MmddyyyyDate;
UINT16 Version;
UINT8 Type;
UINT8 Reserved[5];
UINT64 FwVendorId;
UINT8 Reserved2[40];
} SAL_UPDATE_PAL_DATA_BLOCK;

typedef struct _SAL_UPDATE_PAL_INFO_BLOCK {
struct _SAL_UPDATE_PAL_INFO_BLOCK *Next;
struct SAL_UPDATE_PAL_DATA_BLOCK *DataBlock;
UINT8 StoreChecksum;
UINT8 Reserved[15];
} SAL_UPDATE_PAL_INFO_BLOCK;

#pragma pack(1)
typedef struct {

UINT32 Signature;

UINT32 Length;

UINT16 SalRevision;

UINT16 EntryCount;

UINT8 CheckSum;

UINT8 Reserved[7];

UINT16 SalAVersion;

UINT16 SalBVersion;

UINT8 OemId[32];

UINT8 ProductId[32];

UINT8 Reserved2[8];
} SAL_SYSTEM_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Reserved[7];
UINT64 PalProcEntry;
UINT64 SalProcEntry;
UINT64 SalGlobalDataPointer;
UINT64 Reserved2[2];
} SAL_ST_ENTRY_POINT_DESCRIPTOR;

typedef struct {
UINT8 Type;
UINT8 PlatformFeatures;
UINT8 Reserved[14];
} SAL_ST_PLATFORM_FEATURES;
typedef struct {
UINT8 Type;
UINT8 TRType;
UINT8 TRNumber;
UINT8 Reserved[5];
UINT64 VirtualAddress;
UINT64 EncodedPageSize;
UINT64 Reserved1;
} SAL_ST_TR_DECRIPTOR;
typedef struct {
UINT64 NumberOfProcessors;
UINT64 LocalIDRegister;
} SAL_COHERENCE_DOMAIN_INFO;

typedef struct {
UINT8 Type;
UINT8 Reserved[3];
UINT32 NumberOfDomains;
SAL_COHERENCE_DOMAIN_INFO *DomainInformation;
} SAL_ST_CACHE_COHERENCE_DECRIPTOR;

typedef struct {
UINT8 Type;
UINT8 WakeUpType;
UINT8 Reserved[6];
UINT64 ExternalInterruptVector;
} SAL_ST_AP_WAKEUP_DECRIPTOR;

typedef struct {
UINT64 Address;
UINT8 Size[3];
UINT8 Reserved;
UINT16 Revision;
UINT8 Type : 7;
UINT8 CheckSumValid : 1;
UINT8 CheckSum;
} EFI_SAL_FIT_ENTRY;
typedef struct {
UINT8 Seconds;
UINT8 Minutes;
UINT8 Hours;
UINT8 Reserved;
UINT8 Day;
UINT8 Month;
UINT8 Year;
UINT8 Century;
} SAL_TIME_STAMP;

typedef struct {
UINT64 RecordId;
UINT16 Revision;
UINT8 ErrorSeverity;
UINT8 ValidationBits;
UINT32 RecordLength;
SAL_TIME_STAMP TimeStamp;
UINT8 OemPlatformId[16];
} SAL_RECORD_HEADER;

typedef struct {
GUID Guid;
UINT16 Revision;
UINT8 ErrorRecoveryInfo;
UINT8 Reserved;
UINT32 SectionLength;
} SAL_SEC_HEADER;
typedef struct {
UINT64 InfoValid : 1;
UINT64 ReqValid : 1;
UINT64 RespValid : 1;
UINT64 TargetValid : 1;
UINT64 IpValid : 1;
UINT64 Reserved : 59;
UINT64 Info;
UINT64 Req;
UINT64 Resp;
UINT64 Target;
UINT64 Ip;
} MOD_ERROR_INFO;

typedef struct {
UINT8 CpuidInfo[40];
UINT8 Reserved;
} CPUID_INFO;

typedef struct {
UINT64 FrLow;
UINT64 FrHigh;
} FR_STRUCT;
typedef struct {
UINT64 ValidFieldBits;
UINT8 MinStateInfo[1024];
UINT64 Br[8];
UINT64 Cr[128];
UINT64 Ar[128];
UINT64 Rr[8];
FR_STRUCT Fr[128];
} PSI_STATIC_STRUCT;
typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT64 ProcErrorMap;
UINT64 ProcStateParameter;
UINT64 ProcCrLid;
MOD_ERROR_INFO CacheError[15];
MOD_ERROR_INFO TlbError[15];
MOD_ERROR_INFO BusError[15];
MOD_ERROR_INFO RegFileCheck[15];
MOD_ERROR_INFO MsCheck[15];
CPUID_INFO CpuInfo;
PSI_STATIC_STRUCT PsiValidData;
} SAL_PROCESSOR_ERROR_RECORD;
typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT64 MemErrorStatus;
UINT64 MemPhysicalAddress;
UINT64 MemPhysicalAddressMask;
UINT16 MemNode;
UINT16 MemCard;
UINT16 MemModule;
UINT16 MemBank;
UINT16 MemDevice;
UINT16 MemRow;
UINT16 MemColumn;
UINT16 MemBitPosition;
UINT64 ModRequestorId;
UINT64 ModResponderId;
UINT64 ModTargetId;
UINT64 BusSpecificData;
UINT8 MemPlatformOemId[16];
} SAL_MEMORY_ERROR_RECORD;
typedef struct {
UINT8 BusNumber;
UINT8 SegmentNumber;
} PCI_BUS_ID;

typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT64 PciBusErrorStatus;
UINT16 PciBusErrorType;
PCI_BUS_ID PciBusId;
UINT32 Reserved;
UINT64 PciBusAddress;
UINT64 PciBusData;
UINT64 PciBusCommand;
UINT64 PciBusRequestorId;
UINT64 PciBusResponderId;
UINT64 PciBusTargetId;
UINT8 PciBusOemId[16];
} SAL_PCI_BUS_ERROR_RECORD;
typedef struct {
UINT16 VendorId;
UINT16 DeviceId;
UINT8 ClassCode[3];
UINT8 FunctionNumber;
UINT8 DeviceNumber;
UINT8 BusNumber;
UINT8 SegmentNumber;
UINT8 Reserved[5];
} PCI_COMP_INFO;

typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT64 PciComponentErrorStatus;
PCI_COMP_INFO PciComponentInfo;
UINT32 PciComponentMemNum;
UINT32 PciComponentIoNum;
UINT8 PciBusOemId[16];
} SAL_PCI_COMPONENT_ERROR_RECORD;
typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT16 SelRecordId;
UINT8 SelRecordType;
UINT32 TimeStamp;
UINT16 GeneratorId;
UINT8 EvmRevision;
UINT8 SensorType;
UINT8 SensorNum;
UINT8 EventDirType;
UINT8 Data1;
UINT8 Data2;
UINT8 Data3;
} SAL_SEL_DEVICE_ERROR_RECORD;
typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT8 SmbiosEventType;
UINT8 SmbiosLength;
UINT8 SmbiosBcdTimeStamp[6];
} SAL_SMBIOS_DEVICE_ERROR_RECORD;
typedef struct {
SAL_SEC_HEADER SectionHeader;
UINT64 ValidationBits;
UINT64 PlatformErrorStatus;
UINT64 PlatformRequestorId;
UINT64 PlatformResponderId;
UINT64 PlatformTargetId;
UINT64 PlatformBusSpecificData;
UINT8 OemComponentId[16];
} SAL_PLATFORM_SPECIFIC_ERROR_RECORD;

typedef union {
SAL_RECORD_HEADER *RecordHeader;
SAL_PROCESSOR_ERROR_RECORD *SalProcessorRecord;
SAL_PCI_BUS_ERROR_RECORD *SalPciBusRecord;
SAL_PCI_COMPONENT_ERROR_RECORD *SalPciComponentRecord;
SAL_SEL_DEVICE_ERROR_RECORD *ImpiRecord;
SAL_SMBIOS_DEVICE_ERROR_RECORD *SmbiosRecord;
SAL_PLATFORM_SPECIFIC_ERROR_RECORD *PlatformRecord;
SAL_MEMORY_ERROR_RECORD *MemoryRecord;
UINT8 *Raw;
} SAL_ERROR_RECORDS_POINTERS;

#pragma pack()

typedef struct _EXTENDED_SAL_BOOT_SERVICE_PROTOCOL EXTENDED_SAL_BOOT_SERVICE_PROTOCOL;
typedef
EFI_STATUS
( *EXTENDED_SAL_ADD_SST_INFO)(
EXTENDED_SAL_BOOT_SERVICE_PROTOCOL *This,
UINT16 SalAVersion,
UINT16 SalBVersion,
CHAR8 *OemId,
CHAR8 *ProductId
);
typedef
EFI_STATUS
( *EXTENDED_SAL_ADD_SST_ENTRY)(
EXTENDED_SAL_BOOT_SERVICE_PROTOCOL *This,
UINT8 *TableEntry,
UINTN EntrySize
);
typedef
SAL_RETURN_REGS
( *SAL_INTERNAL_EXTENDED_SAL_PROC)(
UINT64 FunctionId,
UINT64 Arg2,
UINT64 Arg3,
UINT64 Arg4,
UINT64 Arg5,
UINT64 Arg6,
UINT64 Arg7,
UINT64 Arg8,
BOOLEAN VirtualMode,
void *ModuleGlobal
);
typedef
EFI_STATUS
( *EXTENDED_SAL_REGISTER_INTERNAL_PROC)(
EXTENDED_SAL_BOOT_SERVICE_PROTOCOL *This,
UINT64 ClassGuidLo,
UINT64 ClassGuidHi,
UINT64 FunctionId,
SAL_INTERNAL_EXTENDED_SAL_PROC InternalSalProc,
void *PhysicalModuleGlobal
);
typedef
SAL_RETURN_REGS
( *EXTENDED_SAL_PROC)(
UINT64 ClassGuidLo,
UINT64 ClassGuidHi,
UINT64 FunctionId,
UINT64 Arg2,
UINT64 Arg3,
UINT64 Arg4,
UINT64 Arg5,
UINT64 Arg6,
UINT64 Arg7,
UINT64 Arg8
);

struct _EXTENDED_SAL_BOOT_SERVICE_PROTOCOL {
EXTENDED_SAL_ADD_SST_INFO AddSalSystemTableInfo;
EXTENDED_SAL_ADD_SST_ENTRY AddSalSystemTableEntry;
EXTENDED_SAL_REGISTER_INTERNAL_PROC RegisterExtendedSalProc;
EXTENDED_SAL_PROC ExtendedSalProc;
};

extern EFI_GUID gEfiExtendedSalBootServiceProtocolGuid;
typedef enum {
IoReadFunctionId,
IoWriteFunctionId,
MemReadFunctionId,
MemWriteFunctionId
} EFI_EXTENDED_SAL_BASE_IO_SERVICES_FUNC_ID;
typedef enum {
StallFunctionId
} EFI_EXTENDED_SAL_STALL_FUNC_ID;
typedef enum {
GetTimeFunctionId,
SetTimeFunctionId,
GetWakeupTimeFunctionId,
SetWakeupTimeFunctionId,
GetRtcFreqFunctionId,
InitializeThresholdFunctionId,
BumpThresholdCountFunctionId,
GetThresholdCountFunctionId
} EFI_EXTENDED_SAL_RTC_SERVICES_FUNC_ID;
typedef enum {
EsalGetVariableFunctionId,
EsalGetNextVariableNameFunctionId,
EsalSetVariableFunctionId,
EsalQueryVariableInfoFunctionId
} EFI_EXTENDED_SAL_VARIABLE_SERVICES_FUNC_ID;
typedef enum {
GetNextHighMonotonicCountFunctionId
} EFI_EXTENDED_SAL_MTC_SERVICES_FUNC_ID;
typedef enum {
ResetSystemFunctionId
} EFI_EXTENDED_SAL_RESET_SERVICES_FUNC_ID;
typedef enum {
ReportStatusCodeServiceFunctionId
} EFI_EXTENDED_SAL_STATUS_CODE_SERVICES_FUNC_ID;
typedef enum {
ReadFunctionId,
WriteFunctionId,
EraseBlockFunctionId,
GetVolumeAttributesFunctionId,
SetVolumeAttributesFunctionId,
GetPhysicalAddressFunctionId,
GetBlockSizeFunctionId,
} EFI_EXTENDED_SAL_FV_BLOCK_SERVICES_FUNC_ID;
typedef enum {
AddCpuDataFunctionId,
RemoveCpuDataFunctionId,
ModifyCpuDataFunctionId,
GetCpuDataByIDFunctionId,
GetCpuDataByIndexFunctionId,
SendIpiFunctionId,
CurrentProcInfoFunctionId,
NumProcessorsFunctionId,
SetMinStateFunctionId,
GetMinStateFunctionId
} EFI_EXTENDED_SAL_MP_SERVICES_FUNC_ID;
typedef enum {
PalProcFunctionId,
SetNewPalEntryFunctionId,
GetNewPalEntryFunctionId,
EsalUpdatePalFunctionId
} EFI_EXTENDED_SAL_PAL_SERVICES_FUNC_ID;
typedef enum {
SalSetVectorsFunctionId,
SalMcRendezFunctionId,
SalMcSetParamsFunctionId,
EsalGetVectorsFunctionId,
EsalMcGetParamsFunctionId,
EsalMcGetMcParamsFunctionId,
EsalGetMcCheckinFlagsFunctionId,
EsalGetPlatformBaseFreqFunctionId,
EsalPhysicalIdInfoFunctionId,
EsalRegisterPhysicalAddrFunctionId
} EFI_EXTENDED_SAL_BASE_SERVICES_FUNC_ID;
typedef enum {
McaGetStateInfoFunctionId,
McaRegisterCpuFunctionId
} EFI_EXTENDED_SAL_MCA_SERVICES_FUNC_ID;
typedef enum {
SalPciConfigReadFunctionId,
SalPciConfigWriteFunctionId
} EFI_EXTENDED_SAL_PCI_SERVICES_FUNC_ID;
typedef enum {
SalCacheInitFunctionId,
SalCacheFlushFunctionId
} EFI_EXTENDED_SAL_CACHE_SERVICES_FUNC_ID;
typedef enum {
SalGetStateInfoFunctionId,
SalGetStateInfoSizeFunctionId,
SalClearStateInfoFunctionId,
EsalGetStateBufferFunctionId,
EsalSaveStateBufferFunctionId
} EFI_EXTENDED_SAL_MCA_LOG_SERVICES_FUNC_ID;
typedef struct _EFI_FIRMWARE_MANAGEMENT_PROTOCOL EFI_FIRMWARE_MANAGEMENT_PROTOCOL;

typedef struct {

UINT8 ImageIndex;

EFI_GUID ImageTypeId;

UINT64 ImageId;

CHAR16 *ImageIdName;

UINT32 Version;

CHAR16 *VersionName;

UINTN Size;

UINT64 AttributesSupported;

UINT64 AttributesSetting;

UINT64 Compatibilities;
} EFI_FIRMWARE_IMAGE_DESCRIPTOR;
typedef struct {

UINT64 MonotonicCount;

WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_FIRMWARE_IMAGE_AUTHENTICATION;
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS)(
UINTN Completion
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE_INFO)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
UINTN *ImageInfoSize,
EFI_FIRMWARE_IMAGE_DESCRIPTOR *ImageInfo,
UINT32 *DescriptorVersion,
UINT8 *DescriptorCount,
UINTN *DescriptorSize,
UINT32 *PackageVersion,
CHAR16 **PackageVersionName
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
UINT8 ImageIndex,
void *Image,
UINTN *ImageSize
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_IMAGE)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
UINT8 ImageIndex,
void *Image,
UINTN ImageSize,
void *VendorCode,
EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS Progress,
CHAR16 **AbortReason
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_CHECK_IMAGE)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
UINT8 ImageIndex,
void *Image,
UINTN ImageSize,
UINT32 *ImageUpdatable
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_PACKAGE_INFO)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
UINT32 *PackageVersion,
CHAR16 **PackageVersionName,
UINT32 *PackageVersionNameMaxLen,
UINT64 *AttributesSupported,
UINT64 *AttributesSetting
);
typedef
EFI_STATUS
( *EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_PACKAGE_INFO)(
EFI_FIRMWARE_MANAGEMENT_PROTOCOL *This,
void *Image,
UINTN ImageSize,
void *VendorCode,
UINT32 PackageVersion,
CHAR16 *PackageVersionName
);
struct _EFI_FIRMWARE_MANAGEMENT_PROTOCOL {
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE_INFO GetImageInfo;
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE GetImage;
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_IMAGE SetImage;
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_CHECK_IMAGE CheckImage;
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_PACKAGE_INFO GetPackageInfo;
EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_PACKAGE_INFO SetPackageInfo;
};

extern EFI_GUID gEfiFirmwareManagementProtocolGuid;
typedef struct _EFI_FIRMWARE_VOLUME2_PROTOCOL EFI_FIRMWARE_VOLUME2_PROTOCOL;

typedef UINT64 EFI_FV_ATTRIBUTES;
typedef
EFI_STATUS
( * EFI_FV_GET_ATTRIBUTES)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_FV_ATTRIBUTES *FvAttributes
);
typedef
EFI_STATUS
( * EFI_FV_SET_ATTRIBUTES)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_FV_ATTRIBUTES *FvAttributes
);
typedef
EFI_STATUS
( * EFI_FV_READ_FILE)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_GUID *NameGuid,
void **Buffer,
UINTN *BufferSize,
EFI_FV_FILETYPE *FoundType,
EFI_FV_FILE_ATTRIBUTES *FileAttributes,
UINT32 *AuthenticationStatus
);
typedef
EFI_STATUS
( * EFI_FV_READ_SECTION)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_GUID *NameGuid,
EFI_SECTION_TYPE SectionType,
UINTN SectionInstance,
void **Buffer,
UINTN *BufferSize,
UINT32 *AuthenticationStatus
);

typedef UINT32 EFI_FV_WRITE_POLICY;

typedef struct {

EFI_GUID *NameGuid;

EFI_FV_FILETYPE Type;

EFI_FV_FILE_ATTRIBUTES FileAttributes;

void *Buffer;

UINT32 BufferSize;
} EFI_FV_WRITE_FILE_DATA;
typedef
EFI_STATUS
( * EFI_FV_WRITE_FILE)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
UINT32 NumberOfFiles,
EFI_FV_WRITE_POLICY WritePolicy,
EFI_FV_WRITE_FILE_DATA *FileData
);
typedef
EFI_STATUS
( * EFI_FV_GET_NEXT_FILE)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
void *Key,
EFI_FV_FILETYPE *FileType,
EFI_GUID *NameGuid,
EFI_FV_FILE_ATTRIBUTES *Attributes,
UINTN *Size
);
typedef
EFI_STATUS
( *EFI_FV_GET_INFO)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_GUID *InformationType,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_FV_SET_INFO)(
EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
EFI_GUID *InformationType,
UINTN BufferSize,
void *Buffer
);
struct _EFI_FIRMWARE_VOLUME2_PROTOCOL {
EFI_FV_GET_ATTRIBUTES GetVolumeAttributes;
EFI_FV_SET_ATTRIBUTES SetVolumeAttributes;
EFI_FV_READ_FILE ReadFile;
EFI_FV_READ_SECTION ReadSection;
EFI_FV_WRITE_FILE WriteFile;
EFI_FV_GET_NEXT_FILE GetNextFile;

UINT32 KeySize;

EFI_HANDLE ParentHandle;
EFI_FV_GET_INFO GetInfo;
EFI_FV_SET_INFO SetInfo;
};

extern EFI_GUID gEfiFirmwareVolume2ProtocolGuid;
typedef struct _EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL;

typedef EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL;
typedef
EFI_STATUS
( * EFI_FVB_GET_ATTRIBUTES)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_FVB_ATTRIBUTES_2 *Attributes
);
typedef
EFI_STATUS
( * EFI_FVB_SET_ATTRIBUTES)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_FVB_ATTRIBUTES_2 *Attributes
);
typedef
EFI_STATUS
( * EFI_FVB_GET_PHYSICAL_ADDRESS)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_PHYSICAL_ADDRESS *Address
);
typedef
EFI_STATUS
( * EFI_FVB_GET_BLOCK_SIZE)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_LBA Lba,
UINTN *BlockSize,
UINTN *NumberOfBlocks
);
typedef
EFI_STATUS
( *EFI_FVB_READ)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_LBA Lba,
UINTN Offset,
UINTN *NumBytes,
UINT8 *Buffer
);
typedef
EFI_STATUS
( * EFI_FVB_WRITE)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
EFI_LBA Lba,
UINTN Offset,
UINTN *NumBytes,
UINT8 *Buffer
);
typedef
EFI_STATUS
( * EFI_FVB_ERASE_BLOCKS)(
EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
...
);
struct _EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL{
EFI_FVB_GET_ATTRIBUTES GetAttributes;
EFI_FVB_SET_ATTRIBUTES SetAttributes;
EFI_FVB_GET_PHYSICAL_ADDRESS GetPhysicalAddress;
EFI_FVB_GET_BLOCK_SIZE GetBlockSize;
EFI_FVB_READ Read;
EFI_FVB_WRITE Write;
EFI_FVB_ERASE_BLOCKS EraseBlocks;

EFI_HANDLE ParentHandle;
};

extern EFI_GUID gEfiFirmwareVolumeBlockProtocolGuid;
extern EFI_GUID gEfiFirmwareVolumeBlock2ProtocolGuid;
extern EFI_GUID gEfiHiiPlatformSetupFormsetGuid;
extern EFI_GUID gEfiHiiDriverHealthFormsetGuid;
extern EFI_GUID gEfiHiiUserCredentialFormsetGuid;

typedef struct _EFI_FORM_BROWSER2_PROTOCOL EFI_FORM_BROWSER2_PROTOCOL;
typedef struct {
UINTN LeftColumn;
UINTN RightColumn;
UINTN TopRow;
UINTN BottomRow;
} EFI_SCREEN_DESCRIPTOR;

typedef UINTN EFI_BROWSER_ACTION_REQUEST;
typedef
EFI_STATUS
( *EFI_SEND_FORM2)(
EFI_FORM_BROWSER2_PROTOCOL *This,
EFI_HII_HANDLE *Handle,
UINTN HandleCount,
EFI_GUID *FormSetGuid,
EFI_FORM_ID FormId,
EFI_SCREEN_DESCRIPTOR *ScreenDimensions,
EFI_BROWSER_ACTION_REQUEST *ActionRequest
);
typedef
EFI_STATUS
( *EFI_BROWSER_CALLBACK2)(
EFI_FORM_BROWSER2_PROTOCOL *This,
UINTN *ResultsDataSize,
EFI_STRING ResultsData,
BOOLEAN RetrieveData,
EFI_GUID *VariableGuid,
CHAR16 *VariableName
);

struct _EFI_FORM_BROWSER2_PROTOCOL {
EFI_SEND_FORM2 SendForm;
EFI_BROWSER_CALLBACK2 BrowserCallback;
} ;

extern EFI_GUID gEfiFormBrowser2ProtocolGuid;
typedef struct _EFI_FTP4_PROTOCOL EFI_FTP4_PROTOCOL;

typedef struct {

EFI_EVENT Event;
EFI_STATUS Status;
} EFI_FTP4_CONNECTION_TOKEN;

typedef struct {

UINT8 *Username;

UINT8 *Password;

BOOLEAN Active;

BOOLEAN UseDefaultSetting;

EFI_IPv4_ADDRESS StationIp;

EFI_IPv4_ADDRESS SubnetMask;

EFI_IPv4_ADDRESS GatewayIp;

EFI_IPv4_ADDRESS ServerIp;

UINT16 ServerPort;

UINT16 AltDataPort;
UINT8 RepType;

UINT8 FileStruct;

UINT8 TransMode;
} EFI_FTP4_CONFIG_DATA;

typedef struct _EFI_FTP4_COMMAND_TOKEN EFI_FTP4_COMMAND_TOKEN;
typedef
EFI_STATUS
( *EFI_FTP4_DATA_CALLBACK)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_COMMAND_TOKEN *Token
);

struct _EFI_FTP4_COMMAND_TOKEN {
EFI_EVENT Event;

UINT8 *Pathname;

UINT64 DataBufferSize;

void *DataBuffer;
EFI_FTP4_DATA_CALLBACK *DataCallback;

void *Context;
EFI_STATUS Status;
};
typedef
EFI_STATUS
( *EFI_FTP4_GET_MODE_DATA)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_CONFIG_DATA *ModeData
);
typedef
EFI_STATUS
( *EFI_FTP4_CONNECT)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_CONNECTION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_FTP4_CLOSE)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_CONNECTION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_FTP4_CONFIGURE)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_CONFIG_DATA *FtpConfigData
);
typedef
EFI_STATUS
( *EFI_FTP4_READ_FILE)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_COMMAND_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_FTP4_WRITE_FILE)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_COMMAND_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_FTP4_READ_DIRECTORY)(
EFI_FTP4_PROTOCOL *This,
EFI_FTP4_COMMAND_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_FTP4_POLL)(
EFI_FTP4_PROTOCOL *This
);

struct _EFI_FTP4_PROTOCOL {
EFI_FTP4_GET_MODE_DATA GetModeData;
EFI_FTP4_CONNECT Connect;
EFI_FTP4_CLOSE Close;
EFI_FTP4_CONFIGURE Configure;
EFI_FTP4_READ_FILE ReadFile;
EFI_FTP4_WRITE_FILE WriteFile;
EFI_FTP4_READ_DIRECTORY ReadDirectory;
EFI_FTP4_POLL Poll;
};

extern EFI_GUID gEfiFtp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiFtp4ProtocolGuid;

typedef struct _EFI_GUIDED_SECTION_EXTRACTION_PROTOCOL EFI_GUIDED_SECTION_EXTRACTION_PROTOCOL;
typedef
EFI_STATUS
( *EFI_EXTRACT_GUIDED_SECTION)(
EFI_GUIDED_SECTION_EXTRACTION_PROTOCOL *This,
void *InputSection,
void **OutputBuffer,
UINTN *OutputSize,
UINT32 *AuthenticationStatus
);
struct _EFI_GUIDED_SECTION_EXTRACTION_PROTOCOL {
EFI_EXTRACT_GUIDED_SECTION ExtractSection;
};
typedef struct _EFI_HASH_PROTOCOL EFI_HASH_PROTOCOL;

typedef UINT8 EFI_MD5_HASH[16];
typedef UINT8 EFI_SHA1_HASH[20];
typedef UINT8 EFI_SHA224_HASH[28];
typedef UINT8 EFI_SHA256_HASH[32];
typedef UINT8 EFI_SHA384_HASH[48];
typedef UINT8 EFI_SHA512_HASH[64];

typedef union {
EFI_MD5_HASH *Md5Hash;
EFI_SHA1_HASH *Sha1Hash;
EFI_SHA224_HASH *Sha224Hash;
EFI_SHA256_HASH *Sha256Hash;
EFI_SHA384_HASH *Sha384Hash;
EFI_SHA512_HASH *Sha512Hash;
} EFI_HASH_OUTPUT;
typedef
EFI_STATUS
( *EFI_HASH_GET_HASH_SIZE)(
EFI_HASH_PROTOCOL *This,
EFI_GUID *HashAlgorithm,
UINTN *HashSize
);
typedef
EFI_STATUS
( *EFI_HASH_HASH)(
EFI_HASH_PROTOCOL *This,
EFI_GUID *HashAlgorithm,
BOOLEAN Extend,
UINT8 *Message,
UINT64 MessageSize,
EFI_HASH_OUTPUT *Hash
);

struct _EFI_HASH_PROTOCOL {
EFI_HASH_GET_HASH_SIZE GetHashSize;
EFI_HASH_HASH Hash;
};

extern EFI_GUID gEfiHashServiceBindingProtocolGuid;
extern EFI_GUID gEfiHashProtocolGuid;
extern EFI_GUID gEfiHashAlgorithmSha1Guid;
extern EFI_GUID gEfiHashAlgorithmSha224Guid;
extern EFI_GUID gEfiHashAlgorithmSha256Guid;
extern EFI_GUID gEfiHashAlgorithmSha384Guid;
extern EFI_GUID gEfiHashAlgorithmSha512Guid;
extern EFI_GUID gEfiHashAlgorithmMD5Guid;
extern EFI_GUID gEfiHashAlgorithmSha1NoPadGuid;
extern EFI_GUID gEfiHashAlgorithmSha256NoPadGuid;
typedef struct _EFI_HII_CONFIG_ACCESS_PROTOCOL EFI_HII_CONFIG_ACCESS_PROTOCOL;

typedef UINTN EFI_BROWSER_ACTION;
typedef
EFI_STATUS
( * EFI_HII_ACCESS_EXTRACT_CONFIG)(
EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
EFI_STRING Request,
EFI_STRING *Progress,
EFI_STRING *Results
);
typedef
EFI_STATUS
( * EFI_HII_ACCESS_ROUTE_CONFIG)(
EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
EFI_STRING Configuration,
EFI_STRING *Progress
);
typedef
EFI_STATUS
( *EFI_HII_ACCESS_FORM_CALLBACK)(
EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
EFI_BROWSER_ACTION Action,
EFI_QUESTION_ID QuestionId,
UINT8 Type,
EFI_IFR_TYPE_VALUE *Value,
EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
;

struct _EFI_HII_CONFIG_ACCESS_PROTOCOL {
EFI_HII_ACCESS_EXTRACT_CONFIG ExtractConfig;
EFI_HII_ACCESS_ROUTE_CONFIG RouteConfig;
EFI_HII_ACCESS_FORM_CALLBACK Callback;
} ;

extern EFI_GUID gEfiHiiConfigAccessProtocolGuid;
typedef struct _EFI_HII_CONFIG_ROUTING_PROTOCOL EFI_HII_CONFIG_ROUTING_PROTOCOL;
typedef
EFI_STATUS
( * EFI_HII_EXTRACT_CONFIG)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING Request,
EFI_STRING *Progress,
EFI_STRING *Results
);
typedef
EFI_STATUS
( * EFI_HII_EXPORT_CONFIG)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING *Results
);
typedef
EFI_STATUS
( * EFI_HII_ROUTE_CONFIG)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING Configuration,
EFI_STRING *Progress
);
typedef
EFI_STATUS
( * EFI_HII_BLOCK_TO_CONFIG)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING ConfigRequest,
UINT8 *Block,
UINTN BlockSize,
EFI_STRING *Config,
EFI_STRING *Progress
);
typedef
EFI_STATUS
( * EFI_HII_CONFIG_TO_BLOCK)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING ConfigResp,
UINT8 *Block,
UINTN *BlockSize,
EFI_STRING *Progress
);
typedef
EFI_STATUS
( * EFI_HII_GET_ALT_CFG)(
EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
EFI_STRING ConfigResp,
EFI_GUID *Guid,
EFI_STRING Name,
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
UINT16 *AltCfgId,
EFI_STRING *AltCfgResp
);

struct _EFI_HII_CONFIG_ROUTING_PROTOCOL {
EFI_HII_EXTRACT_CONFIG ExtractConfig;
EFI_HII_EXPORT_CONFIG ExportConfig;
EFI_HII_ROUTE_CONFIG RouteConfig;
EFI_HII_BLOCK_TO_CONFIG BlockToConfig;
EFI_HII_CONFIG_TO_BLOCK ConfigToBlock;
EFI_HII_GET_ALT_CFG GetAltConfig;
};

extern EFI_GUID gEfiHiiConfigRoutingProtocolGuid;
typedef struct _EFI_HII_DATABASE_PROTOCOL EFI_HII_DATABASE_PROTOCOL;

typedef UINTN EFI_HII_DATABASE_NOTIFY_TYPE;
typedef
EFI_STATUS
( *EFI_HII_DATABASE_NOTIFY)(
UINT8 PackageType,
EFI_GUID *PackageGuid,
EFI_HII_PACKAGE_HEADER *Package,
EFI_HII_HANDLE Handle,
EFI_HII_DATABASE_NOTIFY_TYPE NotifyType
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_NEW_PACK)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HII_PACKAGE_LIST_HEADER *PackageList,
EFI_HANDLE DriverHandle,
EFI_HII_HANDLE *Handle
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_REMOVE_PACK)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HII_HANDLE Handle
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_UPDATE_PACK)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HII_HANDLE Handle,
EFI_HII_PACKAGE_LIST_HEADER *PackageList
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_LIST_PACKS)(
EFI_HII_DATABASE_PROTOCOL *This,
UINT8 PackageType,
EFI_GUID *PackageGuid,
UINTN *HandleBufferLength,
EFI_HII_HANDLE *Handle
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_EXPORT_PACKS)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HII_HANDLE Handle,
UINTN *BufferSize,
EFI_HII_PACKAGE_LIST_HEADER *Buffer
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_REGISTER_NOTIFY)(
EFI_HII_DATABASE_PROTOCOL *This,
UINT8 PackageType,
EFI_GUID *PackageGuid,
EFI_HII_DATABASE_NOTIFY PackageNotifyFn,
EFI_HII_DATABASE_NOTIFY_TYPE NotifyType,
EFI_HANDLE *NotifyHandle
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_UNREGISTER_NOTIFY)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HANDLE NotificationHandle
);
typedef
EFI_STATUS
( *EFI_HII_FIND_KEYBOARD_LAYOUTS)(
EFI_HII_DATABASE_PROTOCOL *This,
UINT16 *KeyGuidBufferLength,
EFI_GUID *KeyGuidBuffer
);
typedef
EFI_STATUS
( *EFI_HII_GET_KEYBOARD_LAYOUT)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_GUID *KeyGuid,
UINT16 *KeyboardLayoutLength,
EFI_HII_KEYBOARD_LAYOUT *KeyboardLayout
);
typedef
EFI_STATUS
( *EFI_HII_SET_KEYBOARD_LAYOUT)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_GUID *KeyGuid
);
typedef
EFI_STATUS
( *EFI_HII_DATABASE_GET_PACK_HANDLE)(
EFI_HII_DATABASE_PROTOCOL *This,
EFI_HII_HANDLE PackageListHandle,
EFI_HANDLE *DriverHandle
);

struct _EFI_HII_DATABASE_PROTOCOL {
EFI_HII_DATABASE_NEW_PACK NewPackageList;
EFI_HII_DATABASE_REMOVE_PACK RemovePackageList;
EFI_HII_DATABASE_UPDATE_PACK UpdatePackageList;
EFI_HII_DATABASE_LIST_PACKS ListPackageLists;
EFI_HII_DATABASE_EXPORT_PACKS ExportPackageLists;
EFI_HII_DATABASE_REGISTER_NOTIFY RegisterPackageNotify;
EFI_HII_DATABASE_UNREGISTER_NOTIFY UnregisterPackageNotify;
EFI_HII_FIND_KEYBOARD_LAYOUTS FindKeyboardLayouts;
EFI_HII_GET_KEYBOARD_LAYOUT GetKeyboardLayout;
EFI_HII_SET_KEYBOARD_LAYOUT SetKeyboardLayout;
EFI_HII_DATABASE_GET_PACK_HANDLE GetPackageListHandle;
};

extern EFI_GUID gEfiHiiDatabaseProtocolGuid;
typedef struct _EFI_HII_IMAGE_PROTOCOL EFI_HII_IMAGE_PROTOCOL;
typedef struct _EFI_IMAGE_INPUT {
UINT32 Flags;
UINT16 Width;
UINT16 Height;
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Bitmap;
} EFI_IMAGE_INPUT;
typedef
EFI_STATUS
( *EFI_HII_NEW_IMAGE)(
EFI_HII_IMAGE_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
EFI_IMAGE_ID *ImageId,
EFI_IMAGE_INPUT *Image
);
typedef
EFI_STATUS
( *EFI_HII_GET_IMAGE)(
EFI_HII_IMAGE_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
EFI_IMAGE_ID ImageId,
EFI_IMAGE_INPUT *Image
);
typedef
EFI_STATUS
( *EFI_HII_SET_IMAGE)(
EFI_HII_IMAGE_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
EFI_IMAGE_ID ImageId,
EFI_IMAGE_INPUT *Image
);

typedef UINT32 EFI_HII_DRAW_FLAGS;
typedef struct _EFI_IMAGE_OUTPUT {
UINT16 Width;
UINT16 Height;
union {
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Bitmap;
EFI_GRAPHICS_OUTPUT_PROTOCOL *Screen;
} Image;
} EFI_IMAGE_OUTPUT;
typedef
EFI_STATUS
( *EFI_HII_DRAW_IMAGE)(
EFI_HII_IMAGE_PROTOCOL *This,
EFI_HII_DRAW_FLAGS Flags,
EFI_IMAGE_INPUT *Image,
EFI_IMAGE_OUTPUT **Blt,
UINTN BltX,
UINTN BltY
);
typedef
EFI_STATUS
( *EFI_HII_DRAW_IMAGE_ID)(
EFI_HII_IMAGE_PROTOCOL *This,
EFI_HII_DRAW_FLAGS Flags,
EFI_HII_HANDLE PackageList,
EFI_IMAGE_ID ImageId,
EFI_IMAGE_OUTPUT **Blt,
UINTN BltX,
UINTN BltY
);

struct _EFI_HII_IMAGE_PROTOCOL {
EFI_HII_NEW_IMAGE NewImage;
EFI_HII_GET_IMAGE GetImage;
EFI_HII_SET_IMAGE SetImage;
EFI_HII_DRAW_IMAGE DrawImage;
EFI_HII_DRAW_IMAGE_ID DrawImageId;
};

extern EFI_GUID gEfiHiiImageProtocolGuid;

typedef struct _EFI_HII_FONT_PROTOCOL EFI_HII_FONT_PROTOCOL;

typedef void *EFI_FONT_HANDLE;

typedef UINT32 EFI_HII_OUT_FLAGS;
typedef struct _EFI_HII_ROW_INFO {

UINTN StartIndex;

UINTN EndIndex;
UINTN LineHeight;
UINTN LineWidth;

UINTN BaselineOffset;
} EFI_HII_ROW_INFO;

typedef UINT32 EFI_FONT_INFO_MASK;
typedef struct {
EFI_HII_FONT_STYLE FontStyle;
UINT16 FontSize;
CHAR16 FontName[1];
} EFI_FONT_INFO;
typedef struct _EFI_FONT_DISPLAY_INFO {
EFI_GRAPHICS_OUTPUT_BLT_PIXEL ForegroundColor;
EFI_GRAPHICS_OUTPUT_BLT_PIXEL BackgroundColor;
EFI_FONT_INFO_MASK FontInfoMask;
EFI_FONT_INFO FontInfo;
} EFI_FONT_DISPLAY_INFO;
typedef
EFI_STATUS
( *EFI_HII_STRING_TO_IMAGE)(
EFI_HII_FONT_PROTOCOL *This,
EFI_HII_OUT_FLAGS Flags,
EFI_STRING String,
EFI_FONT_DISPLAY_INFO *StringInfo,
EFI_IMAGE_OUTPUT **Blt,
UINTN BltX,
UINTN BltY,
EFI_HII_ROW_INFO **RowInfoArray ,
UINTN *RowInfoArraySize ,
UINTN *ColumnInfoArray
);
typedef
EFI_STATUS
( *EFI_HII_STRING_ID_TO_IMAGE)(
EFI_HII_FONT_PROTOCOL *This,
EFI_HII_OUT_FLAGS Flags,
EFI_HII_HANDLE PackageList,
EFI_STRING_ID StringId,
CHAR8 *Language,
EFI_FONT_DISPLAY_INFO *StringInfo ,
EFI_IMAGE_OUTPUT **Blt,
UINTN BltX,
UINTN BltY,
EFI_HII_ROW_INFO **RowInfoArray ,
UINTN *RowInfoArraySize ,
UINTN *ColumnInfoArray
);
typedef
EFI_STATUS
( *EFI_HII_GET_GLYPH)(
EFI_HII_FONT_PROTOCOL *This,
CHAR16 Char,
EFI_FONT_DISPLAY_INFO *StringInfo,
EFI_IMAGE_OUTPUT **Blt,
UINTN *Baseline
);
typedef
EFI_STATUS
( *EFI_HII_GET_FONT_INFO)(
EFI_HII_FONT_PROTOCOL *This,
EFI_FONT_HANDLE *FontHandle,
EFI_FONT_DISPLAY_INFO *StringInfoIn,
EFI_FONT_DISPLAY_INFO **StringInfoOut,
EFI_STRING String
);

struct _EFI_HII_FONT_PROTOCOL {
EFI_HII_STRING_TO_IMAGE StringToImage;
EFI_HII_STRING_ID_TO_IMAGE StringIdToImage;
EFI_HII_GET_GLYPH GetGlyph;
EFI_HII_GET_FONT_INFO GetFontInfo;
};

extern EFI_GUID gEfiHiiFontProtocolGuid;

typedef EFI_HII_PACKAGE_LIST_HEADER * EFI_HII_PACKAGE_LIST_PROTOCOL;

extern EFI_GUID gEfiHiiPackageListProtocolGuid;
typedef struct _EFI_HII_STRING_PROTOCOL EFI_HII_STRING_PROTOCOL;
typedef
EFI_STATUS
( *EFI_HII_NEW_STRING)(
EFI_HII_STRING_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
EFI_STRING_ID *StringId,
CHAR8 *Language,
CHAR16 *LanguageName,
EFI_STRING String,
EFI_FONT_INFO *StringFontInfo
);
typedef
EFI_STATUS
( *EFI_HII_GET_STRING)(
EFI_HII_STRING_PROTOCOL *This,
CHAR8 *Language,
EFI_HII_HANDLE PackageList,
EFI_STRING_ID StringId,
EFI_STRING String,
UINTN *StringSize,
EFI_FONT_INFO **StringFontInfo
);
typedef
EFI_STATUS
( *EFI_HII_SET_STRING)(
EFI_HII_STRING_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
EFI_STRING_ID StringId,
CHAR8 *Language,
EFI_STRING String,
EFI_FONT_INFO *StringFontInfo
);
typedef
EFI_STATUS
( *EFI_HII_GET_LANGUAGES)(
EFI_HII_STRING_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
CHAR8 *Languages,
UINTN *LanguagesSize
);
typedef
EFI_STATUS
( *EFI_HII_GET_2ND_LANGUAGES)(
EFI_HII_STRING_PROTOCOL *This,
EFI_HII_HANDLE PackageList,
CHAR8 *PrimaryLanguage,
CHAR8 *SecondaryLanguages,
UINTN *SecondaryLanguagesSize
);

struct _EFI_HII_STRING_PROTOCOL {
EFI_HII_NEW_STRING NewString;
EFI_HII_GET_STRING GetString;
EFI_HII_SET_STRING SetString;
EFI_HII_GET_LANGUAGES GetLanguages;
EFI_HII_GET_2ND_LANGUAGES GetSecondaryLanguages;
};

extern EFI_GUID gEfiHiiStringProtocolGuid;
typedef struct _EFI_ISCSI_INITIATOR_NAME_PROTOCOL EFI_ISCSI_INITIATOR_NAME_PROTOCOL;
typedef
EFI_STATUS
( *EFI_ISCSI_INITIATOR_NAME_GET)(
EFI_ISCSI_INITIATOR_NAME_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef EFI_STATUS
( *EFI_ISCSI_INITIATOR_NAME_SET)(
EFI_ISCSI_INITIATOR_NAME_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);

struct _EFI_ISCSI_INITIATOR_NAME_PROTOCOL {
EFI_ISCSI_INITIATOR_NAME_GET Get;
EFI_ISCSI_INITIATOR_NAME_SET Set;
};

extern EFI_GUID gEfiIScsiInitiatorNameProtocolGuid;
#pragma pack(1)

typedef struct {
UINT16 config;
UINT16 cylinders;
UINT16 reserved_2;
UINT16 heads;
UINT16 vendor_data1;
UINT16 vendor_data2;
UINT16 sectors_per_track;
UINT16 vendor_specific_7_9[3];
CHAR8 SerialNo[20];
UINT16 vendor_specific_20_21[2];
UINT16 ecc_bytes_available;
CHAR8 FirmwareVer[8];
CHAR8 ModelName[40];
UINT16 multi_sector_cmd_max_sct_cnt;
UINT16 reserved_48;
UINT16 capabilities;
UINT16 reserved_50;
UINT16 pio_cycle_timing;
UINT16 reserved_52;
UINT16 field_validity;
UINT16 current_cylinders;
UINT16 current_heads;
UINT16 current_sectors;
UINT16 CurrentCapacityLsb;
UINT16 CurrentCapacityMsb;
UINT16 reserved_59;
UINT16 user_addressable_sectors_lo;
UINT16 user_addressable_sectors_hi;
UINT16 reserved_62;
UINT16 multi_word_dma_mode;
UINT16 advanced_pio_modes;
UINT16 min_multi_word_dma_cycle_time;
UINT16 rec_multi_word_dma_cycle_time;
UINT16 min_pio_cycle_time_without_flow_control;
UINT16 min_pio_cycle_time_with_flow_control;
UINT16 reserved_69_79[11];
UINT16 major_version_no;
UINT16 minor_version_no;
UINT16 command_set_supported_82;
UINT16 command_set_supported_83;
UINT16 command_set_feature_extn;
UINT16 command_set_feature_enb_85;
UINT16 command_set_feature_enb_86;
UINT16 command_set_feature_default;
UINT16 ultra_dma_mode;
UINT16 reserved_89_127[39];
UINT16 security_status;
UINT16 vendor_data_129_159[31];
UINT16 reserved_160_255[96];
} ATA5_IDENTIFY_DATA;

typedef struct {
UINT16 config;
UINT16 obsolete_1;
UINT16 specific_config;
UINT16 obsolete_3;
UINT16 retired_4_5[2];
UINT16 obsolete_6;
UINT16 cfa_reserved_7_8[2];
UINT16 retired_9;
CHAR8 SerialNo[20];
UINT16 retired_20_21[2];
UINT16 obsolete_22;
CHAR8 FirmwareVer[8];
CHAR8 ModelName[40];
UINT16 multi_sector_cmd_max_sct_cnt;
UINT16 trusted_computing_support;
UINT16 capabilities_49;
UINT16 capabilities_50;
UINT16 obsolete_51_52[2];
UINT16 field_validity;
UINT16 obsolete_54_58[5];
UINT16 multi_sector_setting;
UINT16 user_addressable_sectors_lo;
UINT16 user_addressable_sectors_hi;
UINT16 obsolete_62;
UINT16 multi_word_dma_mode;
UINT16 advanced_pio_modes;
UINT16 min_multi_word_dma_cycle_time;
UINT16 rec_multi_word_dma_cycle_time;
UINT16 min_pio_cycle_time_without_flow_control;
UINT16 min_pio_cycle_time_with_flow_control;
UINT16 reserved_69_74[6];
UINT16 queue_depth;
UINT16 reserved_76_79[4];
UINT16 major_version_no;
UINT16 minor_version_no;
UINT16 command_set_supported_82;
UINT16 command_set_supported_83;
UINT16 command_set_feature_extn;
UINT16 command_set_feature_enb_85;
UINT16 command_set_feature_enb_86;
UINT16 command_set_feature_default;
UINT16 ultra_dma_mode;
UINT16 time_for_security_erase_unit;
UINT16 time_for_enhanced_security_erase_unit;
UINT16 advanced_power_management_level;
UINT16 master_password_identifier;
UINT16 hardware_configuration_test_result;
UINT16 acoustic_management_value;
UINT16 stream_minimum_request_size;
UINT16 streaming_transfer_time_for_dma;
UINT16 streaming_access_latency_for_dma_and_pio;
UINT16 streaming_performance_granularity[2];
UINT16 maximum_lba_for_48bit_addressing[4];
UINT16 streaming_transfer_time_for_pio;
UINT16 reserved_105;
UINT16 phy_logic_sector_support;
UINT16 interseek_delay_for_iso7779;
UINT16 world_wide_name[4];
UINT16 reserved_for_128bit_wwn_112_115[4];
UINT16 reserved_for_technical_report;
UINT16 logic_sector_size_lo;
UINT16 logic_sector_size_hi;
UINT16 features_and_command_sets_supported_ext;
UINT16 features_and_command_sets_enabled_ext;
UINT16 reserved_121_126[6];
UINT16 obsolete_127;
UINT16 security_status;
UINT16 vendor_specific_129_159[31];
UINT16 cfa_power_mode;
UINT16 reserved_for_compactflash_161_175[15];
CHAR8 media_serial_number[60];
UINT16 sct_command_transport;
UINT16 reserved_207_208[2];
UINT16 alignment_logic_in_phy_blocks;
UINT16 write_read_verify_sector_count_mode3[2];
UINT16 verify_sector_count_mode2[2];
UINT16 nv_cache_capabilities;
UINT16 nv_cache_size_in_logical_block_lsw;
UINT16 nv_cache_size_in_logical_block_msw;
UINT16 nv_cache_read_speed;
UINT16 nv_cache_write_speed;
UINT16 nv_cache_options;
UINT16 write_read_verify_mode;
UINT16 reserved_221;
UINT16 transport_major_revision_number;
UINT16 transport_minor_revision_number;
UINT16 reserved_224_233[10];
UINT16 min_number_per_download_microcode_mode3;
UINT16 max_number_per_download_microcode_mode3;
UINT16 reserved_236_254[19];
UINT16 integrity_word;
} ATA_IDENTIFY_DATA;

typedef struct {
UINT16 config;
UINT16 reserved_1;
UINT16 specific_config;
UINT16 reserved_3_9[7];
CHAR8 SerialNo[20];
UINT16 reserved_20_22[3];
CHAR8 FirmwareVer[8];
CHAR8 ModelName[40];
UINT16 reserved_47_48[2];
UINT16 capabilities_49;
UINT16 capabilities_50;
UINT16 obsolete_51;
UINT16 reserved_52;
UINT16 field_validity;
UINT16 reserved_54_61[8];
UINT16 dma_dir;
UINT16 multi_word_dma_mode;
UINT16 advanced_pio_modes;
UINT16 min_multi_word_dma_cycle_time;
UINT16 rec_multi_word_dma_cycle_time;
UINT16 min_pio_cycle_time_without_flow_control;
UINT16 min_pio_cycle_time_with_flow_control;
UINT16 reserved_69_70[2];
UINT16 obsolete_71_72[2];
UINT16 reserved_73_74[2];
UINT16 queue_depth;
UINT16 reserved_76_79[4];
UINT16 major_version_no;
UINT16 minor_version_no;
UINT16 cmd_set_support_82;
UINT16 cmd_set_support_83;
UINT16 cmd_feature_support;
UINT16 cmd_feature_enable_85;
UINT16 cmd_feature_enable_86;
UINT16 cmd_feature_default;
UINT16 ultra_dma_select;
UINT16 time_required_for_sec_erase;
UINT16 time_required_for_enhanced_sec_erase;
UINT16 reserved_91;
UINT16 master_pwd_revison_code;
UINT16 hardware_reset_result;
UINT16 current_auto_acoustic_mgmt_value;
UINT16 reserved_95_107[13];
UINT16 world_wide_name[4];
UINT16 reserved_for_128bit_wwn_112_115[4];
UINT16 reserved_116_124[9];
UINT16 atapi_byte_count_0_behavior;
UINT16 obsolete_126;
UINT16 removable_media_status_notification_support;
UINT16 security_status;
UINT16 reserved_129_160[32];
UINT16 cfa_reserved_161_175[15];
UINT16 reserved_176_254[79];
UINT16 integrity_word;
} ATAPI_IDENTIFY_DATA;

typedef struct {
UINT8 peripheral_type;
UINT8 RMB;
UINT8 version;
UINT8 response_data_format;
UINT8 addnl_length;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 reserved_7;
UINT8 vendor_info[8];
UINT8 product_id[16];
UINT8 product_revision_level[4];
UINT8 vendor_specific_36_55[55 - 36 + 1];
UINT8 reserved_56_95[95 - 56 + 1];

UINT8 vendor_specific_96_253[253 - 96 + 1];
} ATAPI_INQUIRY_DATA;

typedef struct {
UINT8 error_code : 7;
UINT8 valid : 1;
UINT8 reserved_1;
UINT8 sense_key : 4;
UINT8 reserved_2 : 1;
UINT8 Vendor_specifc_1 : 3;
UINT8 vendor_specific_3;
UINT8 vendor_specific_4;
UINT8 vendor_specific_5;
UINT8 vendor_specific_6;
UINT8 addnl_sense_length;
UINT8 vendor_specific_8;
UINT8 vendor_specific_9;
UINT8 vendor_specific_10;
UINT8 vendor_specific_11;
UINT8 addnl_sense_code;
UINT8 addnl_sense_code_qualifier;
UINT8 field_replaceable_unit_code;
UINT8 sense_key_specific_15 : 7;
UINT8 SKSV : 1;
UINT8 sense_key_specific_16;
UINT8 sense_key_specific_17;
} ATAPI_REQUEST_SENSE_DATA;

typedef struct {
UINT8 LastLba3;
UINT8 LastLba2;
UINT8 LastLba1;
UINT8 LastLba0;
UINT8 BlockSize3;
UINT8 BlockSize2;
UINT8 BlockSize1;
UINT8 BlockSize0;
} ATAPI_READ_CAPACITY_DATA;

typedef struct {
UINT8 reserved_0;
UINT8 reserved_1;
UINT8 reserved_2;
UINT8 Capacity_Length;
UINT8 LastLba3;
UINT8 LastLba2;
UINT8 LastLba1;
UINT8 LastLba0;
UINT8 DesCode : 2;
UINT8 reserved_9 : 6;
UINT8 BlockSize2;
UINT8 BlockSize1;
UINT8 BlockSize0;
} ATAPI_READ_FORMAT_CAPACITY_DATA;

typedef struct {
UINT8 opcode;
UINT8 reserved_1;
UINT8 reserved_2;
UINT8 reserved_3;
UINT8 reserved_4;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 reserved_7;
UINT8 reserved_8;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_TEST_UNIT_READY_CMD;

typedef struct {
UINT8 opcode;
UINT8 reserved_1 : 5;
UINT8 lun : 3;
UINT8 page_code;
UINT8 reserved_3;
UINT8 allocation_length;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 reserved_7;
UINT8 reserved_8;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_INQUIRY_CMD;

typedef struct {
UINT8 opcode;
UINT8 reserved_1 : 5;
UINT8 lun : 3;
UINT8 reserved_2;
UINT8 reserved_3;
UINT8 allocation_length;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 reserved_7;
UINT8 reserved_8;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_REQUEST_SENSE_CMD;

typedef struct {
UINT8 opcode;
UINT8 reserved_1 : 5;
UINT8 lun : 3;
UINT8 Lba0;
UINT8 Lba1;
UINT8 Lba2;
UINT8 Lba3;
UINT8 reserved_6;
UINT8 TranLen0;
UINT8 TranLen1;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_READ10_CMD;

typedef struct {
UINT8 opcode;
UINT8 reserved_1 : 5;
UINT8 lun : 3;
UINT8 reserved_2;
UINT8 reserved_3;
UINT8 reserved_4;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 allocation_length_hi;
UINT8 allocation_length_lo;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_READ_FORMAT_CAP_CMD;

typedef struct {
UINT8 opcode;
UINT8 reserved_1 : 5;
UINT8 lun : 3;
UINT8 page_code : 6;
UINT8 page_control : 2;
UINT8 reserved_3;
UINT8 reserved_4;
UINT8 reserved_5;
UINT8 reserved_6;
UINT8 parameter_list_length_hi;
UINT8 parameter_list_length_lo;
UINT8 reserved_9;
UINT8 reserved_10;
UINT8 reserved_11;
} ATAPI_MODE_SENSE_CMD;

typedef union {
UINT16 Data16[6];
ATAPI_TEST_UNIT_READY_CMD TestUnitReady;
ATAPI_READ10_CMD Read10;
ATAPI_REQUEST_SENSE_CMD RequestSence;
ATAPI_INQUIRY_CMD Inquiry;
ATAPI_MODE_SENSE_CMD ModeSense;
ATAPI_READ_FORMAT_CAP_CMD ReadFormatCapacity;
} ATAPI_PACKET_COMMAND;

#pragma pack()
typedef struct _EFI_IDE_CONTROLLER_INIT_PROTOCOL EFI_IDE_CONTROLLER_INIT_PROTOCOL;

typedef enum {

EfiIdeBeforeChannelEnumeration,

EfiIdeAfterChannelEnumeration,

EfiIdeBeforeChannelReset,

EfiIdeAfterChannelReset,

EfiIdeBusBeforeDevicePresenceDetection,

EfiIdeBusAfterDevicePresenceDetection,

EfiIdeResetMode,
EfiIdeBusPhaseMaximum
} EFI_IDE_CONTROLLER_ENUM_PHASE;

typedef enum {
EfiAtaSataTransferProtocol
} EFI_ATA_EXT_TRANSFER_PROTOCOL;
typedef struct {
BOOLEAN Valid;
UINT32 Mode;
} EFI_ATA_MODE;

typedef struct {
EFI_ATA_EXT_TRANSFER_PROTOCOL TransferProtocol;

UINT32 Mode;
} EFI_ATA_EXTENDED_MODE;

typedef struct {

EFI_ATA_MODE PioMode;
EFI_ATA_MODE SingleWordDmaMode;

EFI_ATA_MODE MultiWordDmaMode;

EFI_ATA_MODE UdmaMode;

UINT32 ExtModeCount;

EFI_ATA_EXTENDED_MODE ExtMode[1];
} EFI_ATA_COLLECTIVE_MODE;
typedef ATA_IDENTIFY_DATA EFI_ATA_IDENTIFY_DATA;
typedef ATAPI_IDENTIFY_DATA EFI_ATAPI_IDENTIFY_DATA;
typedef union {

EFI_ATA_IDENTIFY_DATA AtaData;

EFI_ATAPI_IDENTIFY_DATA AtapiData;
} EFI_IDENTIFY_DATA;
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_GET_CHANNEL_INFO)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
UINT8 Channel,
BOOLEAN *Enabled,
UINT8 *MaxDevices
);
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_NOTIFY_PHASE)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
EFI_IDE_CONTROLLER_ENUM_PHASE Phase,
UINT8 Channel
);
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_SUBMIT_DATA)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
UINT8 Channel,
UINT8 Device,
EFI_IDENTIFY_DATA *IdentifyData
);
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_DISQUALIFY_MODE)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
UINT8 Channel,
UINT8 Device,
EFI_ATA_COLLECTIVE_MODE *BadModes
);
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_CALCULATE_MODE)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
UINT8 Channel,
UINT8 Device,
EFI_ATA_COLLECTIVE_MODE **SupportedModes
);
typedef
EFI_STATUS
( *EFI_IDE_CONTROLLER_SET_TIMING)(
EFI_IDE_CONTROLLER_INIT_PROTOCOL *This,
UINT8 Channel,
UINT8 Device,
EFI_ATA_COLLECTIVE_MODE *Modes
);

struct _EFI_IDE_CONTROLLER_INIT_PROTOCOL {

EFI_IDE_CONTROLLER_GET_CHANNEL_INFO GetChannelInfo;

EFI_IDE_CONTROLLER_NOTIFY_PHASE NotifyPhase;

EFI_IDE_CONTROLLER_SUBMIT_DATA SubmitData;

EFI_IDE_CONTROLLER_DISQUALIFY_MODE DisqualifyMode;

EFI_IDE_CONTROLLER_CALCULATE_MODE CalculateMode;

EFI_IDE_CONTROLLER_SET_TIMING SetTiming;

BOOLEAN EnumAll;
UINT8 ChannelCount;
};

extern EFI_GUID gEfiIdeControllerInitProtocolGuid;
typedef struct _EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL;
typedef
EFI_STATUS
( *EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_CHECK_DEVICE)(
EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL *This,
UINTN VendorId,
UINTN DeviceId,
UINTN RevisionId,
UINTN SubsystemVendorId,
UINTN SubsystemDeviceId,
void **Configuration
);

struct _EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_PROTOCOL {

EFI_INCOMPATIBLE_PCI_DEVICE_SUPPORT_CHECK_DEVICE CheckDevice;
};

extern EFI_GUID gEfiIncompatiblePciDeviceSupportProtocolGuid;
typedef struct _EFI_SIMPLE_NETWORK_PROTOCOL EFI_SIMPLE_NETWORK_PROTOCOL;

typedef EFI_SIMPLE_NETWORK_PROTOCOL EFI_SIMPLE_NETWORK;

typedef struct {

UINT64 RxTotalFrames;

UINT64 RxGoodFrames;

UINT64 RxUndersizeFrames;

UINT64 RxOversizeFrames;

UINT64 RxDroppedFrames;

UINT64 RxUnicastFrames;

UINT64 RxBroadcastFrames;

UINT64 RxMulticastFrames;

UINT64 RxCrcErrorFrames;

UINT64 RxTotalBytes;

UINT64 TxTotalFrames;
UINT64 TxGoodFrames;
UINT64 TxUndersizeFrames;
UINT64 TxOversizeFrames;
UINT64 TxDroppedFrames;
UINT64 TxUnicastFrames;
UINT64 TxBroadcastFrames;
UINT64 TxMulticastFrames;
UINT64 TxCrcErrorFrames;
UINT64 TxTotalBytes;

UINT64 Collisions;

UINT64 UnsupportedProtocol;

} EFI_NETWORK_STATISTICS;

typedef enum {
EfiSimpleNetworkStopped,
EfiSimpleNetworkStarted,
EfiSimpleNetworkInitialized,
EfiSimpleNetworkMaxState
} EFI_SIMPLE_NETWORK_STATE;
typedef struct {

UINT32 State;

UINT32 HwAddressSize;

UINT32 MediaHeaderSize;

UINT32 MaxPacketSize;

UINT32 NvRamSize;

UINT32 NvRamAccessSize;

UINT32 ReceiveFilterMask;

UINT32 ReceiveFilterSetting;

UINT32 MaxMCastFilterCount;

UINT32 MCastFilterCount;

EFI_MAC_ADDRESS MCastFilter[16];

EFI_MAC_ADDRESS CurrentAddress;

EFI_MAC_ADDRESS BroadcastAddress;

EFI_MAC_ADDRESS PermanentAddress;

UINT8 IfType;

BOOLEAN MacAddressChangeable;

BOOLEAN MultipleTxSupported;

BOOLEAN MediaPresentSupported;

BOOLEAN MediaPresent;
} EFI_SIMPLE_NETWORK_MODE;
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_START)(
EFI_SIMPLE_NETWORK_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_STOP)(
EFI_SIMPLE_NETWORK_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_INITIALIZE)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
UINTN ExtraRxBufferSize ,
UINTN ExtraTxBufferSize
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_RESET)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_SHUTDOWN)(
EFI_SIMPLE_NETWORK_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_RECEIVE_FILTERS)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
UINT32 Enable,
UINT32 Disable,
BOOLEAN ResetMCastFilter,
UINTN MCastFilterCnt ,
EFI_MAC_ADDRESS *MCastFilter
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_STATION_ADDRESS)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
BOOLEAN Reset,
EFI_MAC_ADDRESS *New
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_STATISTICS)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
BOOLEAN Reset,
UINTN *StatisticsSize ,
EFI_NETWORK_STATISTICS *StatisticsTable
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_MCAST_IP_TO_MAC)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
BOOLEAN IPv6,
EFI_IP_ADDRESS *IP,
EFI_MAC_ADDRESS *MAC
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_NVDATA)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
BOOLEAN ReadWrite,
UINTN Offset,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_GET_STATUS)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
UINT32 *InterruptStatus ,
void **TxBuf
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_TRANSMIT)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
UINTN HeaderSize,
UINTN BufferSize,
void *Buffer,
EFI_MAC_ADDRESS *SrcAddr ,
EFI_MAC_ADDRESS *DestAddr ,
UINT16 *Protocol
);
typedef
EFI_STATUS
( *EFI_SIMPLE_NETWORK_RECEIVE)(
EFI_SIMPLE_NETWORK_PROTOCOL *This,
UINTN *HeaderSize ,
UINTN *BufferSize,
void *Buffer,
EFI_MAC_ADDRESS *SrcAddr ,
EFI_MAC_ADDRESS *DestAddr ,
UINT16 *Protocol
);
struct _EFI_SIMPLE_NETWORK_PROTOCOL {

UINT64 Revision;
EFI_SIMPLE_NETWORK_START Start;
EFI_SIMPLE_NETWORK_STOP Stop;
EFI_SIMPLE_NETWORK_INITIALIZE Initialize;
EFI_SIMPLE_NETWORK_RESET Reset;
EFI_SIMPLE_NETWORK_SHUTDOWN Shutdown;
EFI_SIMPLE_NETWORK_RECEIVE_FILTERS ReceiveFilters;
EFI_SIMPLE_NETWORK_STATION_ADDRESS StationAddress;
EFI_SIMPLE_NETWORK_STATISTICS Statistics;
EFI_SIMPLE_NETWORK_MCAST_IP_TO_MAC MCastIpToMac;
EFI_SIMPLE_NETWORK_NVDATA NvData;
EFI_SIMPLE_NETWORK_GET_STATUS GetStatus;
EFI_SIMPLE_NETWORK_TRANSMIT Transmit;
EFI_SIMPLE_NETWORK_RECEIVE Receive;

EFI_EVENT WaitForPacket;

EFI_SIMPLE_NETWORK_MODE *Mode;
};

extern EFI_GUID gEfiSimpleNetworkProtocolGuid;
typedef struct _EFI_MANAGED_NETWORK_PROTOCOL EFI_MANAGED_NETWORK_PROTOCOL;

typedef struct {

UINT32 ReceivedQueueTimeoutValue;

UINT32 TransmitQueueTimeoutValue;

UINT16 ProtocolTypeFilter;

BOOLEAN EnableUnicastReceive;

BOOLEAN EnableMulticastReceive;

BOOLEAN EnableBroadcastReceive;

BOOLEAN EnablePromiscuousReceive;

BOOLEAN FlushQueuesOnReset;

BOOLEAN EnableReceiveTimestamps;

BOOLEAN DisableBackgroundPolling;
} EFI_MANAGED_NETWORK_CONFIG_DATA;

typedef struct {
EFI_TIME Timestamp;
EFI_EVENT RecycleEvent;
UINT32 PacketLength;
UINT32 HeaderLength;
UINT32 AddressLength;
UINT32 DataLength;
BOOLEAN BroadcastFlag;
BOOLEAN MulticastFlag;
BOOLEAN PromiscuousFlag;
UINT16 ProtocolType;
void *DestinationAddress;
void *SourceAddress;
void *MediaHeader;
void *PacketData;
} EFI_MANAGED_NETWORK_RECEIVE_DATA;

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_MANAGED_NETWORK_FRAGMENT_DATA;

typedef struct {
EFI_MAC_ADDRESS *DestinationAddress;
EFI_MAC_ADDRESS *SourceAddress;
UINT16 ProtocolType;
UINT32 DataLength;
UINT16 HeaderLength;
UINT16 FragmentCount;
EFI_MANAGED_NETWORK_FRAGMENT_DATA FragmentTable[1];
} EFI_MANAGED_NETWORK_TRANSMIT_DATA;

typedef struct {

EFI_EVENT Event;

EFI_STATUS Status;
union {

EFI_MANAGED_NETWORK_RECEIVE_DATA *RxData;

EFI_MANAGED_NETWORK_TRANSMIT_DATA *TxData;
} Packet;
} EFI_MANAGED_NETWORK_COMPLETION_TOKEN;
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_GET_MODE_DATA)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_CONFIGURE)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_MCAST_IP_TO_MAC)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
BOOLEAN Ipv6Flag,
EFI_IP_ADDRESS *IpAddress,
EFI_MAC_ADDRESS *MacAddress
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_GROUPS)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
BOOLEAN JoinFlag,
EFI_MAC_ADDRESS *MacAddress
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_TRANSMIT)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
EFI_MANAGED_NETWORK_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_RECEIVE)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
EFI_MANAGED_NETWORK_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_CANCEL)(
EFI_MANAGED_NETWORK_PROTOCOL *This,
EFI_MANAGED_NETWORK_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MANAGED_NETWORK_POLL)(
EFI_MANAGED_NETWORK_PROTOCOL *This
);

struct _EFI_MANAGED_NETWORK_PROTOCOL {
EFI_MANAGED_NETWORK_GET_MODE_DATA GetModeData;
EFI_MANAGED_NETWORK_CONFIGURE Configure;
EFI_MANAGED_NETWORK_MCAST_IP_TO_MAC McastIpToMac;
EFI_MANAGED_NETWORK_GROUPS Groups;
EFI_MANAGED_NETWORK_TRANSMIT Transmit;
EFI_MANAGED_NETWORK_RECEIVE Receive;
EFI_MANAGED_NETWORK_CANCEL Cancel;
EFI_MANAGED_NETWORK_POLL Poll;
};

extern EFI_GUID gEfiManagedNetworkServiceBindingProtocolGuid;
extern EFI_GUID gEfiManagedNetworkProtocolGuid;
typedef struct _EFI_IP4_PROTOCOL EFI_IP4_PROTOCOL;

typedef struct {
EFI_HANDLE InstanceHandle;
EFI_IPv4_ADDRESS Ip4Address;
EFI_IPv4_ADDRESS SubnetMask;
} EFI_IP4_ADDRESS_PAIR;

typedef struct {
EFI_HANDLE DriverHandle;
UINT32 AddressCount;
EFI_IP4_ADDRESS_PAIR AddressPairs[1];
} EFI_IP4_VARIABLE_DATA;

typedef struct {

UINT8 DefaultProtocol;

BOOLEAN AcceptAnyProtocol;

BOOLEAN AcceptIcmpErrors;

BOOLEAN AcceptBroadcast;

BOOLEAN AcceptPromiscuous;

BOOLEAN UseDefaultAddress;

EFI_IPv4_ADDRESS StationAddress;

EFI_IPv4_ADDRESS SubnetMask;

UINT8 TypeOfService;

UINT8 TimeToLive;

BOOLEAN DoNotFragment;

BOOLEAN RawData;

UINT32 ReceiveTimeout;

UINT32 TransmitTimeout;
} EFI_IP4_CONFIG_DATA;

typedef struct {
EFI_IPv4_ADDRESS SubnetAddress;
EFI_IPv4_ADDRESS SubnetMask;
EFI_IPv4_ADDRESS GatewayAddress;
} EFI_IP4_ROUTE_TABLE;

typedef struct {
UINT8 Type;
UINT8 Code;
} EFI_IP4_ICMP_TYPE;

typedef struct {

BOOLEAN IsStarted;

UINT32 MaxPacketSize;

EFI_IP4_CONFIG_DATA ConfigData;

BOOLEAN IsConfigured;

UINT32 GroupCount;

EFI_IPv4_ADDRESS *GroupTable;

UINT32 RouteCount;

EFI_IP4_ROUTE_TABLE *RouteTable;

UINT32 IcmpTypeCount;

EFI_IP4_ICMP_TYPE *IcmpTypeList;
} EFI_IP4_MODE_DATA;

#pragma pack(1)

typedef struct {
UINT8 HeaderLength:4;
UINT8 Version:4;
UINT8 TypeOfService;
UINT16 TotalLength;
UINT16 Identification;
UINT16 Fragmentation;
UINT8 TimeToLive;
UINT8 Protocol;
UINT16 Checksum;
EFI_IPv4_ADDRESS SourceAddress;
EFI_IPv4_ADDRESS DestinationAddress;
} EFI_IP4_HEADER;
#pragma pack()

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_IP4_FRAGMENT_DATA;

typedef struct {
EFI_TIME TimeStamp;
EFI_EVENT RecycleSignal;
UINT32 HeaderLength;
EFI_IP4_HEADER *Header;
UINT32 OptionsLength;
void *Options;
UINT32 DataLength;
UINT32 FragmentCount;
EFI_IP4_FRAGMENT_DATA FragmentTable[1];
} EFI_IP4_RECEIVE_DATA;

typedef struct {
EFI_IPv4_ADDRESS SourceAddress;
EFI_IPv4_ADDRESS GatewayAddress;
UINT8 Protocol;
UINT8 TypeOfService;
UINT8 TimeToLive;
BOOLEAN DoNotFragment;
} EFI_IP4_OVERRIDE_DATA;

typedef struct {
EFI_IPv4_ADDRESS DestinationAddress;
EFI_IP4_OVERRIDE_DATA *OverrideData;
UINT32 OptionsLength;
void *OptionsBuffer;
UINT32 TotalDataLength;
UINT32 FragmentCount;
EFI_IP4_FRAGMENT_DATA FragmentTable[1];
} EFI_IP4_TRANSMIT_DATA;

typedef struct {

EFI_EVENT Event;

EFI_STATUS Status;
union {

EFI_IP4_RECEIVE_DATA *RxData;

EFI_IP4_TRANSMIT_DATA *TxData;
} Packet;
} EFI_IP4_COMPLETION_TOKEN;
typedef
EFI_STATUS
( *EFI_IP4_GET_MODE_DATA)(
EFI_IP4_PROTOCOL *This,
EFI_IP4_MODE_DATA *Ip4ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_IP4_CONFIGURE)(
EFI_IP4_PROTOCOL *This,
EFI_IP4_CONFIG_DATA *IpConfigData
);
typedef
EFI_STATUS
( *EFI_IP4_GROUPS)(
EFI_IP4_PROTOCOL *This,
BOOLEAN JoinFlag,
EFI_IPv4_ADDRESS *GroupAddress
);
typedef
EFI_STATUS
( *EFI_IP4_ROUTES)(
EFI_IP4_PROTOCOL *This,
BOOLEAN DeleteRoute,
EFI_IPv4_ADDRESS *SubnetAddress,
EFI_IPv4_ADDRESS *SubnetMask,
EFI_IPv4_ADDRESS *GatewayAddress
);
typedef
EFI_STATUS
( *EFI_IP4_TRANSMIT)(
EFI_IP4_PROTOCOL *This,
EFI_IP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP4_RECEIVE)(
EFI_IP4_PROTOCOL *This,
EFI_IP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP4_CANCEL)(
EFI_IP4_PROTOCOL *This,
EFI_IP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP4_POLL)(
EFI_IP4_PROTOCOL *This
);

struct _EFI_IP4_PROTOCOL {
EFI_IP4_GET_MODE_DATA GetModeData;
EFI_IP4_CONFIGURE Configure;
EFI_IP4_GROUPS Groups;
EFI_IP4_ROUTES Routes;
EFI_IP4_TRANSMIT Transmit;
EFI_IP4_RECEIVE Receive;
EFI_IP4_CANCEL Cancel;
EFI_IP4_POLL Poll;
};

extern EFI_GUID gEfiIp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiIp4ProtocolGuid;
typedef struct _EFI_IP4_CONFIG_PROTOCOL EFI_IP4_CONFIG_PROTOCOL;
typedef struct {

EFI_IPv4_ADDRESS StationAddress;

EFI_IPv4_ADDRESS SubnetMask;

UINT32 RouteTableSize;

EFI_IP4_ROUTE_TABLE *RouteTable;
} EFI_IP4_IPCONFIG_DATA;
typedef
EFI_STATUS
( *EFI_IP4_CONFIG_START)(
EFI_IP4_CONFIG_PROTOCOL *This,
EFI_EVENT DoneEvent,
EFI_EVENT ReconfigEvent
);
typedef
EFI_STATUS
( *EFI_IP4_CONFIG_STOP)(
EFI_IP4_CONFIG_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_IP4_CONFIG_GET_DATA)(
EFI_IP4_CONFIG_PROTOCOL *This,
UINTN *IpConfigDataSize,
EFI_IP4_IPCONFIG_DATA *IpConfigData
);

struct _EFI_IP4_CONFIG_PROTOCOL {
EFI_IP4_CONFIG_START Start;
EFI_IP4_CONFIG_STOP Stop;
EFI_IP4_CONFIG_GET_DATA GetData;
};

extern EFI_GUID gEfiIp4ConfigProtocolGuid;
typedef struct _EFI_IP6_PROTOCOL EFI_IP6_PROTOCOL;

typedef struct{

EFI_HANDLE InstanceHandle;

EFI_IPv6_ADDRESS Ip6Address;

UINT8 PrefixLength;
} EFI_IP6_ADDRESS_PAIR;

typedef struct {

EFI_HANDLE DriverHandle;

UINT32 AddressCount;

EFI_IP6_ADDRESS_PAIR AddressPairs[1];
} EFI_IP6_VARIABLE_DATA;
typedef struct {

UINT8 DefaultProtocol;

BOOLEAN AcceptAnyProtocol;

BOOLEAN AcceptIcmpErrors;

BOOLEAN AcceptPromiscuous;

EFI_IPv6_ADDRESS DestinationAddress;
EFI_IPv6_ADDRESS StationAddress;

UINT8 TrafficClass;

UINT8 HopLimit;

UINT32 FlowLabel;

UINT32 ReceiveTimeout;

UINT32 TransmitTimeout;
} EFI_IP6_CONFIG_DATA;

typedef struct {
EFI_IPv6_ADDRESS Address;
UINT8 PrefixLength;
} EFI_IP6_ADDRESS_INFO;

typedef struct {

EFI_IPv6_ADDRESS Gateway;

EFI_IPv6_ADDRESS Destination;

UINT8 PrefixLength;
} EFI_IP6_ROUTE_TABLE;

typedef enum {

EfiNeighborInComplete,

EfiNeighborReachable,

EfiNeighborStale,

EfiNeighborDelay,

EfiNeighborProbe
} EFI_IP6_NEIGHBOR_STATE;

typedef struct {
EFI_IPv6_ADDRESS Neighbor;
EFI_MAC_ADDRESS LinkAddress;
EFI_IP6_NEIGHBOR_STATE State;
} EFI_IP6_NEIGHBOR_CACHE;

typedef struct {
UINT8 Type;
UINT8 Code;
} EFI_IP6_ICMP_TYPE;

typedef struct {

BOOLEAN IsStarted;

UINT32 MaxPacketSize;

EFI_IP6_CONFIG_DATA ConfigData;

BOOLEAN IsConfigured;

UINT32 AddressCount;

EFI_IP6_ADDRESS_INFO *AddressList;

UINT32 GroupCount;

EFI_IPv6_ADDRESS *GroupTable;

UINT32 RouteCount;

EFI_IP6_ROUTE_TABLE *RouteTable;

UINT32 NeighborCount;

EFI_IP6_NEIGHBOR_CACHE *NeighborCache;

UINT32 PrefixCount;

EFI_IP6_ADDRESS_INFO *PrefixTable;

UINT32 IcmpTypeCount;

EFI_IP6_ICMP_TYPE *IcmpTypeList;
} EFI_IP6_MODE_DATA;

#pragma pack(1)
typedef struct _EFI_IP6_HEADER {
UINT8 TrafficClassH:4;
UINT8 Version:4;
UINT8 FlowLabelH:4;
UINT8 TrafficClassL:4;
UINT16 FlowLabelL;
UINT16 PayloadLength;
UINT8 NextHeader;
UINT8 HopLimit;
EFI_IPv6_ADDRESS SourceAddress;
EFI_IPv6_ADDRESS DestinationAddress;
} EFI_IP6_HEADER;
#pragma pack()

typedef struct _EFI_IP6_FRAGMENT_DATA {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_IP6_FRAGMENT_DATA;

typedef struct _EFI_IP6_RECEIVE_DATA {

EFI_TIME TimeStamp;

EFI_EVENT RecycleSignal;

UINT32 HeaderLength;

EFI_IP6_HEADER *Header;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_IP6_FRAGMENT_DATA FragmentTable[1];
} EFI_IP6_RECEIVE_DATA;

typedef struct _EFI_IP6_OVERRIDE_DATA {
UINT8 Protocol;
UINT8 HopLimit;
UINT32 FlowLabel;
} EFI_IP6_OVERRIDE_DATA;

typedef struct _EFI_IP6_TRANSMIT_DATA {

EFI_IPv6_ADDRESS DestinationAddress;

EFI_IP6_OVERRIDE_DATA *OverrideData;

UINT32 ExtHdrsLength;

void *ExtHdrs;

UINT8 NextHeader;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_IP6_FRAGMENT_DATA FragmentTable[1];
} EFI_IP6_TRANSMIT_DATA;

typedef struct {

EFI_EVENT Event;
EFI_STATUS Status;
union {

EFI_IP6_RECEIVE_DATA *RxData;

EFI_IP6_TRANSMIT_DATA *TxData;
} Packet;
} EFI_IP6_COMPLETION_TOKEN;
typedef
EFI_STATUS
( *EFI_IP6_GET_MODE_DATA)(
EFI_IP6_PROTOCOL *This,
EFI_IP6_MODE_DATA *Ip6ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_IP6_CONFIGURE)(
EFI_IP6_PROTOCOL *This,
EFI_IP6_CONFIG_DATA *Ip6ConfigData
);
typedef
EFI_STATUS
( *EFI_IP6_GROUPS)(
EFI_IP6_PROTOCOL *This,
BOOLEAN JoinFlag,
EFI_IPv6_ADDRESS *GroupAddress
);
typedef
EFI_STATUS
( *EFI_IP6_ROUTES)(
EFI_IP6_PROTOCOL *This,
BOOLEAN DeleteRoute,
EFI_IPv6_ADDRESS *Destination ,
UINT8 PrefixLength,
EFI_IPv6_ADDRESS *GatewayAddress
);
typedef
EFI_STATUS
( *EFI_IP6_NEIGHBORS)(
EFI_IP6_PROTOCOL *This,
BOOLEAN DeleteFlag,
EFI_IPv6_ADDRESS *TargetIp6Address,
EFI_MAC_ADDRESS *TargetLinkAddress,
UINT32 Timeout,
BOOLEAN Override
);
typedef
EFI_STATUS
( *EFI_IP6_TRANSMIT)(
EFI_IP6_PROTOCOL *This,
EFI_IP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP6_RECEIVE)(
EFI_IP6_PROTOCOL *This,
EFI_IP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP6_CANCEL)(
EFI_IP6_PROTOCOL *This,
EFI_IP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_IP6_POLL)(
EFI_IP6_PROTOCOL *This
);

struct _EFI_IP6_PROTOCOL {
EFI_IP6_GET_MODE_DATA GetModeData;
EFI_IP6_CONFIGURE Configure;
EFI_IP6_GROUPS Groups;
EFI_IP6_ROUTES Routes;
EFI_IP6_NEIGHBORS Neighbors;
EFI_IP6_TRANSMIT Transmit;
EFI_IP6_RECEIVE Receive;
EFI_IP6_CANCEL Cancel;
EFI_IP6_POLL Poll;
};

extern EFI_GUID gEfiIp6ServiceBindingProtocolGuid;
extern EFI_GUID gEfiIp6ProtocolGuid;
typedef struct _EFI_IP6_CONFIG_PROTOCOL EFI_IP6_CONFIG_PROTOCOL;

typedef enum {

Ip6ConfigDataTypeInterfaceInfo,
Ip6ConfigDataTypeAltInterfaceId,

Ip6ConfigDataTypePolicy,
Ip6ConfigDataTypeDupAddrDetectTransmits,

Ip6ConfigDataTypeManualAddress,
Ip6ConfigDataTypeGateway,
Ip6ConfigDataTypeDnsServer,

Ip6ConfigDataTypeMaximum
} EFI_IP6_CONFIG_DATA_TYPE;

typedef struct {

CHAR16 Name[32];

UINT8 IfType;

UINT32 HwAddressSize;

EFI_MAC_ADDRESS HwAddress;

UINT32 AddressInfoCount;

EFI_IP6_ADDRESS_INFO *AddressInfo;

UINT32 RouteCount;

EFI_IP6_ROUTE_TABLE *RouteTable;
} EFI_IP6_CONFIG_INTERFACE_INFO;

typedef struct {
UINT8 Id[8];
} EFI_IP6_CONFIG_INTERFACE_ID;

typedef enum {
Ip6ConfigPolicyManual,
Ip6ConfigPolicyAutomatic
} EFI_IP6_CONFIG_POLICY;

typedef struct {
UINT32 DupAddrDetectTransmits;
} EFI_IP6_CONFIG_DUP_ADDR_DETECT_TRANSMITS;

typedef struct {
EFI_IPv6_ADDRESS Address;
BOOLEAN IsAnycast;
UINT8 PrefixLength;
} EFI_IP6_CONFIG_MANUAL_ADDRESS;
typedef
EFI_STATUS
( *EFI_IP6_CONFIG_SET_DATA)(
EFI_IP6_CONFIG_PROTOCOL *This,
EFI_IP6_CONFIG_DATA_TYPE DataType,
UINTN DataSize,
void *Data
);
typedef
EFI_STATUS
( *EFI_IP6_CONFIG_GET_DATA)(
EFI_IP6_CONFIG_PROTOCOL *This,
EFI_IP6_CONFIG_DATA_TYPE DataType,
UINTN *DataSize,
void *Data
);
typedef
EFI_STATUS
( *EFI_IP6_CONFIG_REGISTER_NOTIFY)(
EFI_IP6_CONFIG_PROTOCOL *This,
EFI_IP6_CONFIG_DATA_TYPE DataType,
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_IP6_CONFIG_UNREGISTER_NOTIFY)(
EFI_IP6_CONFIG_PROTOCOL *This,
EFI_IP6_CONFIG_DATA_TYPE DataType,
EFI_EVENT Event
);

struct _EFI_IP6_CONFIG_PROTOCOL {
EFI_IP6_CONFIG_SET_DATA SetData;
EFI_IP6_CONFIG_GET_DATA GetData;
EFI_IP6_CONFIG_REGISTER_NOTIFY RegisterDataNotify;
EFI_IP6_CONFIG_UNREGISTER_NOTIFY UnregisterDataNotify;
};

extern EFI_GUID gEfiIp6ConfigProtocolGuid;
typedef struct _EFI_IPSEC_CONFIG_PROTOCOL EFI_IPSEC_CONFIG_PROTOCOL;

typedef enum {
IPsecConfigDataTypeSpd,

IPsecConfigDataTypeSad,
IPsecConfigDataTypePad,
IPsecConfigDataTypeMaximum
} EFI_IPSEC_CONFIG_DATA_TYPE;

typedef struct _EFI_IP_ADDRESS_INFO {
EFI_IP_ADDRESS Address;
UINT8 PrefixLength;
} EFI_IP_ADDRESS_INFO;

typedef struct _EFI_IPSEC_SPD_SELECTOR {

UINT32 LocalAddressCount;

EFI_IP_ADDRESS_INFO *LocalAddress;

UINT32 RemoteAddressCount;

EFI_IP_ADDRESS_INFO *RemoteAddress;

UINT16 NextLayerProtocol;

UINT16 LocalPort;

UINT16 LocalPortRange;

UINT16 RemotePort;

UINT16 RemotePortRange;
} EFI_IPSEC_SPD_SELECTOR;

typedef enum {

EfiIPsecInBound,

EfiIPsecOutBound
} EFI_IPSEC_TRAFFIC_DIR;

typedef enum {

EfiIPsecActionDiscard,

EfiIPsecActionBypass,

EfiIPsecActionProtect
} EFI_IPSEC_ACTION;

typedef struct _EFI_IPSEC_SA_LIFETIME {

UINT64 ByteCount;

UINT64 SoftLifetime;

UINT64 HardLifetime;
} EFI_IPSEC_SA_LIFETIME;

typedef enum {
EfiIPsecTransport,
EfiIPsecTunnel
} EFI_IPSEC_MODE;
typedef enum {
EfiIPsecTunnelClearDf,
EfiIPsecTunnelSetDf,
EfiIPsecTunnelCopyDf
} EFI_IPSEC_TUNNEL_DF_OPTION;

typedef struct _EFI_IPSEC_TUNNEL_OPTION {

EFI_IP_ADDRESS LocalTunnelAddress;

EFI_IP_ADDRESS RemoteTunnelAddress;

EFI_IPSEC_TUNNEL_DF_OPTION DF;
} EFI_IPSEC_TUNNEL_OPTION;

typedef enum {
EfiIPsecAH,
EfiIPsecESP
} EFI_IPSEC_PROTOCOL_TYPE;

typedef struct _EFI_IPSEC_PROCESS_POLICY {

BOOLEAN ExtSeqNum;

BOOLEAN SeqOverflow;

BOOLEAN FragCheck;

EFI_IPSEC_SA_LIFETIME SaLifetime;

EFI_IPSEC_MODE Mode;

EFI_IPSEC_TUNNEL_OPTION *TunnelOption;

EFI_IPSEC_PROTOCOL_TYPE Proto;

UINT8 AuthAlgoId;

UINT8 EncAlgoId;
} EFI_IPSEC_PROCESS_POLICY;

typedef struct _EFI_IPSEC_SA_ID {

UINT32 Spi;

EFI_IPSEC_PROTOCOL_TYPE Proto;

EFI_IP_ADDRESS DestAddress;
} EFI_IPSEC_SA_ID;

typedef struct _EFI_IPSEC_SPD_DATA {

UINT8 Name[128];
UINT32 PackageFlag;

EFI_IPSEC_TRAFFIC_DIR TrafficDirection;

EFI_IPSEC_ACTION Action;

EFI_IPSEC_PROCESS_POLICY *ProcessingPolicy;

UINTN SaIdCount;

EFI_IPSEC_SA_ID SaId[1];
} EFI_IPSEC_SPD_DATA;

typedef struct _EFI_IPSEC_AH_ALGO_INFO {
UINT8 AuthAlgoId;
UINTN AuthKeyLength;
void *AuthKey;
} EFI_IPSEC_AH_ALGO_INFO;
typedef struct _EFI_IPSEC_ESP_ALGO_INFO {
UINT8 EncAlgoId;
UINTN EncKeyLength;
void *EncKey;
UINT8 AuthAlgoId;
UINTN AuthKeyLength;
void *AuthKey;
} EFI_IPSEC_ESP_ALGO_INFO;

typedef union {
EFI_IPSEC_AH_ALGO_INFO AhAlgoInfo;
EFI_IPSEC_ESP_ALGO_INFO EspAlgoInfo;
} EFI_IPSEC_ALGO_INFO;

typedef struct _EFI_IPSEC_SA_DATA {

EFI_IPSEC_MODE Mode;

UINT64 SNCount;

UINT8 AntiReplayWindows;

EFI_IPSEC_ALGO_INFO AlgoInfo;

EFI_IPSEC_SA_LIFETIME SaLifetime;

UINT32 PathMTU;

EFI_IPSEC_SPD_SELECTOR *SpdSelector;

BOOLEAN ManualSet;
} EFI_IPSEC_SA_DATA;

typedef struct _EFI_IPSEC_SA_DATA2 {

EFI_IPSEC_MODE Mode;

UINT64 SNCount;

UINT8 AntiReplayWindows;

EFI_IPSEC_ALGO_INFO AlgoInfo;

EFI_IPSEC_SA_LIFETIME SaLifetime;

UINT32 PathMTU;

EFI_IPSEC_SPD_SELECTOR *SpdSelector;

BOOLEAN ManualSet;

EFI_IP_ADDRESS TunnelSourceAddress;

EFI_IP_ADDRESS TunnelDestinationAddress;
} EFI_IPSEC_SA_DATA2;

typedef struct _EFI_IPSEC_PAD_ID {

BOOLEAN PeerIdValid;
union {

EFI_IP_ADDRESS_INFO IpAddress;

UINT8 PeerId[128];
} Id;
} EFI_IPSEC_PAD_ID;

typedef union {
EFI_IPSEC_SPD_SELECTOR SpdSelector;
EFI_IPSEC_SA_ID SaId;
EFI_IPSEC_PAD_ID PadId;
} EFI_IPSEC_CONFIG_SELECTOR;

typedef enum {
EfiIPsecAuthProtocolIKEv1,
EfiIPsecAuthProtocolIKEv2,
EfiIPsecAuthProtocolMaximum
} EFI_IPSEC_AUTH_PROTOCOL_TYPE;

typedef enum {

EfiIPsecAuthMethodPreSharedSecret,

EfiIPsecAuthMethodCertificates,
EfiIPsecAuthMethodMaximum
} EFI_IPSEC_AUTH_METHOD;

typedef struct _EFI_IPSEC_PAD_DATA {

EFI_IPSEC_AUTH_PROTOCOL_TYPE AuthProtocol;

EFI_IPSEC_AUTH_METHOD AuthMethod;

BOOLEAN IkeIdFlag;

UINTN AuthDataSize;

void *AuthData;

UINTN RevocationDataSize;

void *RevocationData;
} EFI_IPSEC_PAD_DATA;
typedef
EFI_STATUS
( *EFI_IPSEC_CONFIG_SET_DATA)(
EFI_IPSEC_CONFIG_PROTOCOL *This,
EFI_IPSEC_CONFIG_DATA_TYPE DataType,
EFI_IPSEC_CONFIG_SELECTOR *Selector,
void *Data,
EFI_IPSEC_CONFIG_SELECTOR *InsertBefore
);
typedef
EFI_STATUS
( *EFI_IPSEC_CONFIG_GET_DATA)(
EFI_IPSEC_CONFIG_PROTOCOL *This,
EFI_IPSEC_CONFIG_DATA_TYPE DataType,
EFI_IPSEC_CONFIG_SELECTOR *Selector,
UINTN *DataSize,
void *Data
);
typedef
EFI_STATUS
( *EFI_IPSEC_CONFIG_GET_NEXT_SELECTOR)(
EFI_IPSEC_CONFIG_PROTOCOL *This,
EFI_IPSEC_CONFIG_DATA_TYPE DataType,
UINTN *SelectorSize,
EFI_IPSEC_CONFIG_SELECTOR *Selector
);
typedef
EFI_STATUS
( *EFI_IPSEC_CONFIG_REGISTER_NOTIFY)(
EFI_IPSEC_CONFIG_PROTOCOL *This,
EFI_IPSEC_CONFIG_DATA_TYPE DataType,
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_IPSEC_CONFIG_UNREGISTER_NOTIFY)(
EFI_IPSEC_CONFIG_PROTOCOL *This,
EFI_IPSEC_CONFIG_DATA_TYPE DataType,
EFI_EVENT Event
);
struct _EFI_IPSEC_CONFIG_PROTOCOL {
EFI_IPSEC_CONFIG_SET_DATA SetData;
EFI_IPSEC_CONFIG_GET_DATA GetData;
EFI_IPSEC_CONFIG_GET_NEXT_SELECTOR GetNextSelector;
EFI_IPSEC_CONFIG_REGISTER_NOTIFY RegisterDataNotify;
EFI_IPSEC_CONFIG_UNREGISTER_NOTIFY UnregisterDataNotify;
};

extern EFI_GUID gEfiIpSecConfigProtocolGuid;
typedef struct _EFI_IPSEC_PROTOCOL EFI_IPSEC_PROTOCOL;
typedef struct _EFI_IPSEC2_PROTOCOL EFI_IPSEC2_PROTOCOL;

typedef struct _EFI_IPSEC_FRAGMENT_DATA {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_IPSEC_FRAGMENT_DATA;
typedef
EFI_STATUS
( *EFI_IPSEC_PROCESS)(
EFI_IPSEC_PROTOCOL *This,
EFI_HANDLE NicHandle,
UINT8 IpVer,
void *IpHead,
UINT8 *LastHead,
void *OptionsBuffer,
UINT32 OptionsLength,
EFI_IPSEC_FRAGMENT_DATA **FragmentTable,
UINT32 *FragmentCount,
EFI_IPSEC_TRAFFIC_DIR TrafficDirection,
EFI_EVENT *RecycleSignal
);
struct _EFI_IPSEC_PROTOCOL {
EFI_IPSEC_PROCESS Process;
EFI_EVENT DisabledEvent;
BOOLEAN DisabledFlag;
};
typedef
EFI_STATUS
( *EFI_IPSEC_PROCESSEXT) (
EFI_IPSEC2_PROTOCOL *This,
EFI_HANDLE NicHandle,
UINT8 IpVer,
void *IpHead,
UINT8 *LastHead,
void **OptionsBuffer,
UINT32 *OptionsLength,
EFI_IPSEC_FRAGMENT_DATA **FragmentTable,
UINT32 *FragmentCount,
EFI_IPSEC_TRAFFIC_DIR TrafficDirection,
EFI_EVENT *RecycleSignal
);
struct _EFI_IPSEC2_PROTOCOL {
EFI_IPSEC_PROCESSEXT ProcessExt;
EFI_EVENT DisabledEvent;
BOOLEAN DisabledFlag;
};

extern EFI_GUID gEfiIpSecProtocolGuid;
extern EFI_GUID gEfiIpSec2ProtocolGuid;

typedef struct _EFI_KMS_PROTOCOL EFI_KMS_PROTOCOL;
typedef struct {

UINT16 ClientIdSize;

void *ClientId;

UINT8 ClientNameType;

UINT8 ClientNameCount;

void *ClientName;
} EFI_KMS_CLIENT_INFO;

typedef struct {

UINT8 KeyIdentifierSize;

void *KeyIdentifier;

EFI_GUID KeyFormat;

void *KeyValue;
EFI_STATUS KeyStatus;
} EFI_KMS_KEY_DESCRIPTOR;

typedef struct {

UINT16 Tag;

UINT16 Type;

UINT32 Length;

UINT8 KeyAttributeData[1];
} EFI_KMS_DYNAMIC_FIELD;

typedef struct {

UINT32 FieldCount;

EFI_KMS_DYNAMIC_FIELD Field[1];
} EFI_KMS_DYNAMIC_ATTRIBUTE;

typedef struct {

UINT8 KeyAttributeIdentifierType;

UINT8 KeyAttributeIdentifierCount;

void *KeyAttributeIdentifier;
UINT16 KeyAttributeInstance;

UINT16 KeyAttributeType;

UINT16 KeyAttributeValueSize;

void *KeyAttributeValue;
EFI_STATUS KeyAttributeStatus;
} EFI_KMS_KEY_ATTRIBUTE;
typedef
EFI_STATUS
( *EFI_KMS_GET_SERVICE_STATUS) (
EFI_KMS_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_KMS_REGISTER_CLIENT) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_CREATE_KEY) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT16 *KeyDescriptorCount,
EFI_KMS_KEY_DESCRIPTOR *KeyDescriptors,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_GET_KEY) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT16 *KeyDescriptorCount,
EFI_KMS_KEY_DESCRIPTOR *KeyDescriptors,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_ADD_KEY) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT16 *KeyDescriptorCount,
EFI_KMS_KEY_DESCRIPTOR *KeyDescriptors,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_DELETE_KEY) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT16 *KeyDescriptorCount,
EFI_KMS_KEY_DESCRIPTOR *KeyDescriptors,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_GET_KEY_ATTRIBUTES) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT8 *KeyIdentifierSize,
void *KeyIdentifier,
UINT16 *KeyAttributesCount,
EFI_KMS_KEY_ATTRIBUTE *KeyAttributes,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_ADD_KEY_ATTRIBUTES) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT8 *KeyIdentifierSize,
void *KeyIdentifier,
UINT16 *KeyAttributesCount,
EFI_KMS_KEY_ATTRIBUTE *KeyAttributes,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_DELETE_KEY_ATTRIBUTES) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINT8 *KeyIdentifierSize,
void *KeyIdentifier,
UINT16 *KeyAttributesCount,
EFI_KMS_KEY_ATTRIBUTE *KeyAttributes,
UINTN *ClientDataSize ,
void **ClientData
);
typedef
EFI_STATUS
( *EFI_KMS_GET_KEY_BY_ATTRIBUTES) (
EFI_KMS_PROTOCOL *This,
EFI_KMS_CLIENT_INFO *Client,
UINTN *KeyAttributeCount,
EFI_KMS_KEY_ATTRIBUTE *KeyAttributes,
UINTN *KeyDescriptorCount,
EFI_KMS_KEY_DESCRIPTOR *KeyDescriptors,
UINTN *ClientDataSize ,
void **ClientData
);

struct _EFI_KMS_PROTOCOL {

EFI_KMS_GET_SERVICE_STATUS GetServiceStatus;

EFI_KMS_REGISTER_CLIENT RegisterClient;

EFI_KMS_CREATE_KEY CreateKey;

EFI_KMS_GET_KEY GetKey;

EFI_KMS_ADD_KEY AddKey;

EFI_KMS_DELETE_KEY DeleteKey;

EFI_KMS_GET_KEY_ATTRIBUTES GetKeyAttributes;

EFI_KMS_ADD_KEY_ATTRIBUTES AddKeyAttributes;

EFI_KMS_DELETE_KEY_ATTRIBUTES DeleteKeyAttributes;

EFI_KMS_GET_KEY_BY_ATTRIBUTES GetKeyByAttributes;

UINT32 ProtocolVersion;

EFI_GUID ServiceId;

CHAR16 *ServiceName;

UINT32 ServiceVersion;
BOOLEAN ServiceAvailable;

BOOLEAN ClientIdSupported;

BOOLEAN ClientIdRequired;

UINT16 ClientIdMaxSize;

UINT8 ClientNameStringTypes;

BOOLEAN ClientNameRequired;

UINT16 ClientNameMaxCount;

BOOLEAN ClientDataSupported;

UINTN ClientDataMaxSize;

BOOLEAN KeyIdVariableLenSupported;

UINTN KeyIdMaxSize;

UINTN KeyFormatsCount;
EFI_GUID *KeyFormats;

BOOLEAN KeyAttributesSupported;

UINT8 KeyAttributeIdStringTypes;
UINT16 KeyAttributeIdMaxCount;

UINTN KeyAttributesCount;
EFI_KMS_KEY_ATTRIBUTE *KeyAttributes;
};

extern EFI_GUID gEfiKmsFormatGeneric128Guid;
extern EFI_GUID gEfiKmsFormatGeneric160Guid;
extern EFI_GUID gEfiKmsFormatGeneric256Guid;
extern EFI_GUID gEfiKmsFormatGeneric512Guid;
extern EFI_GUID gEfiKmsFormatGeneric1024Guid;
extern EFI_GUID gEfiKmsFormatGeneric2048Guid;
extern EFI_GUID gEfiKmsFormatGeneric3072Guid;
extern EFI_GUID gEfiKmsFormatMd2128Guid;
extern EFI_GUID gEfiKmsFormatMdc2128Guid;
extern EFI_GUID gEfiKmsFormatMd4128Guid;
extern EFI_GUID gEfiKmsFormatMdc4128Guid;
extern EFI_GUID gEfiKmsFormatMd5128Guid;
extern EFI_GUID gEfiKmsFormatMd5sha128Guid;
extern EFI_GUID gEfiKmsFormatSha1160Guid;
extern EFI_GUID gEfiKmsFormatSha256256Guid;
extern EFI_GUID gEfiKmsFormatSha512512Guid;
extern EFI_GUID gEfiKmsFormatAesxts128Guid;
extern EFI_GUID gEfiKmsFormatAesxts256Guid;
extern EFI_GUID gEfiKmsFormatAescbc128Guid;
extern EFI_GUID gEfiKmsFormatAescbc256Guid;
extern EFI_GUID gEfiKmsFormatRsasha11024Guid;
extern EFI_GUID gEfiKmsFormatRsasha12048Guid;
extern EFI_GUID gEfiKmsFormatRsasha2562048Guid;
extern EFI_GUID gEfiKmsFormatRsasha2563072Guid;
extern EFI_GUID gEfiKmsProtocolGuid;
typedef struct _EFI_LEGACY_REGION2_PROTOCOL EFI_LEGACY_REGION2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_LEGACY_REGION2_DECODE)(
EFI_LEGACY_REGION2_PROTOCOL *This,
UINT32 Start,
UINT32 Length,
UINT32 *Granularity,
BOOLEAN *On
);
typedef
EFI_STATUS
( *EFI_LEGACY_REGION2_LOCK)(
EFI_LEGACY_REGION2_PROTOCOL *This,
UINT32 Start,
UINT32 Length,
UINT32 *Granularity
);
typedef
EFI_STATUS
( *EFI_LEGACY_REGION2_BOOT_LOCK)(
EFI_LEGACY_REGION2_PROTOCOL *This,
UINT32 Start,
UINT32 Length,
UINT32 *Granularity
);
typedef
EFI_STATUS
( *EFI_LEGACY_REGION2_UNLOCK)(
EFI_LEGACY_REGION2_PROTOCOL *This,
UINT32 Start,
UINT32 Length,
UINT32 *Granularity
);

typedef enum {
LegacyRegionDecoded,
LegacyRegionNotDecoded,
LegacyRegionWriteEnabled,
LegacyRegionWriteDisabled,
LegacyRegionBootLocked,

LegacyRegionNotLocked
} EFI_LEGACY_REGION_ATTRIBUTE;

typedef struct {

UINT32 Start;

UINT32 Length;

EFI_LEGACY_REGION_ATTRIBUTE Attribute;

UINT32 Granularity;
} EFI_LEGACY_REGION_DESCRIPTOR;
typedef
EFI_STATUS
( *EFI_LEGACY_REGION_GET_INFO)(
EFI_LEGACY_REGION2_PROTOCOL *This,
UINT32 *DescriptorCount,
EFI_LEGACY_REGION_DESCRIPTOR **Descriptor
);
struct _EFI_LEGACY_REGION2_PROTOCOL {
EFI_LEGACY_REGION2_DECODE Decode;
EFI_LEGACY_REGION2_LOCK Lock;
EFI_LEGACY_REGION2_BOOT_LOCK BootLock;
EFI_LEGACY_REGION2_UNLOCK UnLock;
EFI_LEGACY_REGION_GET_INFO GetInfo;
};

extern EFI_GUID gEfiLegacyRegion2ProtocolGuid;
typedef struct _EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE_PROTOCOL;

typedef EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE_INTERFACE;
typedef
EFI_STATUS
( *EFI_LOAD_FILE)(
EFI_LOAD_FILE_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *FilePath,
BOOLEAN BootPolicy,
UINTN *BufferSize,
void *Buffer
);

struct _EFI_LOAD_FILE_PROTOCOL {
EFI_LOAD_FILE LoadFile;
};

extern EFI_GUID gEfiLoadFileProtocolGuid;
typedef struct _EFI_LOAD_FILE2_PROTOCOL EFI_LOAD_FILE2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_LOAD_FILE2)(
EFI_LOAD_FILE2_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *FilePath,
BOOLEAN BootPolicy,
UINTN *BufferSize,
void *Buffer
);

struct _EFI_LOAD_FILE2_PROTOCOL {
EFI_LOAD_FILE2 LoadFile;
};

extern EFI_GUID gEfiLoadFile2ProtocolGuid;
typedef struct {
UINT32 Revision;

EFI_HANDLE ParentHandle;

EFI_SYSTEM_TABLE *SystemTable;

EFI_HANDLE DeviceHandle;
EFI_DEVICE_PATH_PROTOCOL *FilePath;

void *Reserved;

UINT32 LoadOptionsSize;
void *LoadOptions;

void *ImageBase;
UINT64 ImageSize;
EFI_MEMORY_TYPE ImageCodeType;
EFI_MEMORY_TYPE ImageDataType;
EFI_IMAGE_UNLOAD Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

typedef EFI_LOADED_IMAGE_PROTOCOL EFI_LOADED_IMAGE;

extern EFI_GUID gEfiLoadedImageProtocolGuid;
extern EFI_GUID gEfiLoadedImageDevicePathProtocolGuid;

typedef struct _EFI_SAL_MCA_INIT_PMI_PROTOCOL EFI_SAL_MCA_INIT_PMI_PROTOCOL;

#pragma pack(1)

typedef struct {
UINT64 First : 1;
UINT64 Last : 1;
UINT64 EntryCount : 16;
UINT64 DispatchedCount : 16;
UINT64 Reserved : 30;
} SAL_MCA_COUNT_STRUCTURE;

#pragma pack()
typedef
EFI_STATUS
( *EFI_SAL_MCA_HANDLER)(
void *ModuleGlobal,
UINT64 ProcessorStateParameters,
EFI_PHYSICAL_ADDRESS MinstateBase,
UINT64 RendezvouseStateInformation,
UINT64 CpuIndex,
SAL_MCA_COUNT_STRUCTURE *McaCountStructure,
BOOLEAN *CorrectedMachineCheck
);
typedef
EFI_STATUS
( *EFI_SAL_INIT_HANDLER)(
void *ModuleGlobal,
UINT64 ProcessorStateParameters,
EFI_PHYSICAL_ADDRESS MinstateBase,
BOOLEAN McaInProgress,
UINT64 CpuIndex,
SAL_MCA_COUNT_STRUCTURE *McaCountStructure,
BOOLEAN *DumpSwitchPressed
);
typedef
EFI_STATUS
( *EFI_SAL_PMI_HANDLER)(
void *ModuleGlobal,
UINT64 CpuIndex,
UINT64 PmiVector
);
typedef
EFI_STATUS
( *EFI_SAL_REGISTER_MCA_HANDLER)(
EFI_SAL_MCA_INIT_PMI_PROTOCOL *This,
EFI_SAL_MCA_HANDLER McaHandler,
void *ModuleGlobal,
BOOLEAN MakeFirst,
BOOLEAN MakeLast
);
typedef
EFI_STATUS
( *EFI_SAL_REGISTER_INIT_HANDLER)(
EFI_SAL_MCA_INIT_PMI_PROTOCOL *This,
EFI_SAL_INIT_HANDLER InitHandler,
void *ModuleGlobal,
BOOLEAN MakeFirst,
BOOLEAN MakeLast
);
typedef
EFI_STATUS
( *EFI_SAL_REGISTER_PMI_HANDLER)(
EFI_SAL_MCA_INIT_PMI_PROTOCOL *This,
EFI_SAL_PMI_HANDLER PmiHandler,
void *ModuleGlobal,
BOOLEAN MakeFirst,
BOOLEAN MakeLast
);

struct _EFI_SAL_MCA_INIT_PMI_PROTOCOL {
EFI_SAL_REGISTER_MCA_HANDLER RegisterMcaHandler;
EFI_SAL_REGISTER_INIT_HANDLER RegisterInitHandler;
EFI_SAL_REGISTER_PMI_HANDLER RegisterPmiHandler;
BOOLEAN McaInProgress;
BOOLEAN InitInProgress;
BOOLEAN PmiInProgress;
};

extern EFI_GUID gEfiSalMcaInitPmiProtocolGuid;
typedef struct _EFI_METRONOME_ARCH_PROTOCOL EFI_METRONOME_ARCH_PROTOCOL;
typedef
EFI_STATUS
( *EFI_METRONOME_WAIT_FOR_TICK)(
EFI_METRONOME_ARCH_PROTOCOL *This,
UINT32 TickNumber
);

struct _EFI_METRONOME_ARCH_PROTOCOL {
EFI_METRONOME_WAIT_FOR_TICK WaitForTick;
UINT32 TickPeriod;
};

extern EFI_GUID gEfiMetronomeArchProtocolGuid;
extern EFI_GUID gEfiMonotonicCounterArchProtocolGuid;
typedef struct _EFI_MP_SERVICES_PROTOCOL EFI_MP_SERVICES_PROTOCOL;
typedef struct {

UINT32 Package;

UINT32 Core;

UINT32 Thread;
} EFI_CPU_PHYSICAL_LOCATION;

typedef struct {

UINT64 ProcessorId;
UINT32 StatusFlag;

EFI_CPU_PHYSICAL_LOCATION Location;
} EFI_PROCESSOR_INFORMATION;
typedef
EFI_STATUS
( *EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS)(
EFI_MP_SERVICES_PROTOCOL *This,
UINTN *NumberOfProcessors,
UINTN *NumberOfEnabledProcessors
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_GET_PROCESSOR_INFO)(
EFI_MP_SERVICES_PROTOCOL *This,
UINTN ProcessorNumber,
EFI_PROCESSOR_INFORMATION *ProcessorInfoBuffer
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_STARTUP_ALL_APS)(
EFI_MP_SERVICES_PROTOCOL *This,
EFI_AP_PROCEDURE Procedure,
BOOLEAN SingleThread,
EFI_EVENT WaitEvent ,
UINTN TimeoutInMicroSeconds,
void *ProcedureArgument ,
UINTN **FailedCpuList
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_STARTUP_THIS_AP)(
EFI_MP_SERVICES_PROTOCOL *This,
EFI_AP_PROCEDURE Procedure,
UINTN ProcessorNumber,
EFI_EVENT WaitEvent ,
UINTN TimeoutInMicroseconds,
void *ProcedureArgument ,
BOOLEAN *Finished
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_SWITCH_BSP)(
EFI_MP_SERVICES_PROTOCOL *This,
UINTN ProcessorNumber,
BOOLEAN EnableOldBSP
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_ENABLEDISABLEAP)(
EFI_MP_SERVICES_PROTOCOL *This,
UINTN ProcessorNumber,
BOOLEAN EnableAP,
UINT32 *HealthFlag
);
typedef
EFI_STATUS
( *EFI_MP_SERVICES_WHOAMI)(
EFI_MP_SERVICES_PROTOCOL *This,
UINTN *ProcessorNumber
);
struct _EFI_MP_SERVICES_PROTOCOL {
EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS GetNumberOfProcessors;
EFI_MP_SERVICES_GET_PROCESSOR_INFO GetProcessorInfo;
EFI_MP_SERVICES_STARTUP_ALL_APS StartupAllAPs;
EFI_MP_SERVICES_STARTUP_THIS_AP StartupThisAP;
EFI_MP_SERVICES_SWITCH_BSP SwitchBSP;
EFI_MP_SERVICES_ENABLEDISABLEAP EnableDisableAP;
EFI_MP_SERVICES_WHOAMI WhoAmI;
};

extern EFI_GUID gEfiMpServiceProtocolGuid;
typedef struct _EFI_MTFTP4_PROTOCOL EFI_MTFTP4_PROTOCOL;
typedef struct _EFI_MTFTP4_TOKEN EFI_MTFTP4_TOKEN;
#pragma pack(1)

typedef struct {
UINT16 OpCode;
UINT8 Filename[1];
} EFI_MTFTP4_REQ_HEADER;

typedef struct {
UINT16 OpCode;
UINT8 Data[1];
} EFI_MTFTP4_OACK_HEADER;

typedef struct {
UINT16 OpCode;
UINT16 Block;
UINT8 Data[1];
} EFI_MTFTP4_DATA_HEADER;

typedef struct {
UINT16 OpCode;
UINT16 Block[1];
} EFI_MTFTP4_ACK_HEADER;

typedef struct {
UINT16 OpCode;
UINT64 Block;
UINT8 Data[1];
} EFI_MTFTP4_DATA8_HEADER;

typedef struct {
UINT16 OpCode;
UINT64 Block[1];
} EFI_MTFTP4_ACK8_HEADER;

typedef struct {
UINT16 OpCode;
UINT16 ErrorCode;
UINT8 ErrorMessage[1];
} EFI_MTFTP4_ERROR_HEADER;

typedef union {

UINT16 OpCode;

EFI_MTFTP4_REQ_HEADER Rrq;

EFI_MTFTP4_REQ_HEADER Wrq;

EFI_MTFTP4_OACK_HEADER Oack;

EFI_MTFTP4_DATA_HEADER Data;

EFI_MTFTP4_ACK_HEADER Ack;

EFI_MTFTP4_DATA8_HEADER Data8;

EFI_MTFTP4_ACK8_HEADER Ack8;

EFI_MTFTP4_ERROR_HEADER Error;
} EFI_MTFTP4_PACKET;

#pragma pack()

typedef struct {
UINT8 *OptionStr;
UINT8 *ValueStr;
} EFI_MTFTP4_OPTION;

typedef struct {
BOOLEAN UseDefaultSetting;
EFI_IPv4_ADDRESS StationIp;
EFI_IPv4_ADDRESS SubnetMask;
UINT16 LocalPort;
EFI_IPv4_ADDRESS GatewayIp;
EFI_IPv4_ADDRESS ServerIp;
UINT16 InitialServerPort;
UINT16 TryCount;
UINT16 TimeoutValue;
} EFI_MTFTP4_CONFIG_DATA;

typedef struct {
EFI_MTFTP4_CONFIG_DATA ConfigData;
UINT8 SupportedOptionCount;
UINT8 **SupportedOptoins;
UINT8 UnsupportedOptionCount;
UINT8 **UnsupportedOptoins;
} EFI_MTFTP4_MODE_DATA;

typedef struct {
EFI_IPv4_ADDRESS GatewayIp;
EFI_IPv4_ADDRESS ServerIp;
UINT16 ServerPort;
UINT16 TryCount;
UINT16 TimeoutValue;
} EFI_MTFTP4_OVERRIDE_DATA;
typedef
EFI_STATUS
( *EFI_MTFTP4_CHECK_PACKET)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token,
UINT16 PacketLen,
EFI_MTFTP4_PACKET *Paket
);
typedef
EFI_STATUS
( *EFI_MTFTP4_TIMEOUT_CALLBACK)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP4_PACKET_NEEDED)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token,
UINT16 *Length,
void **Buffer
);
typedef
EFI_STATUS
( *EFI_MTFTP4_GET_MODE_DATA)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_MODE_DATA *ModeData
);
typedef
EFI_STATUS
( *EFI_MTFTP4_CONFIGURE)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_CONFIG_DATA *MtftpConfigData
);
typedef
EFI_STATUS
( *EFI_MTFTP4_GET_INFO)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_OVERRIDE_DATA *OverrideData ,
UINT8 *Filename,
UINT8 *ModeStr ,
UINT8 OptionCount,
EFI_MTFTP4_OPTION *OptionList,
UINT32 *PacketLength,
EFI_MTFTP4_PACKET **Packet
);
typedef
EFI_STATUS
( *EFI_MTFTP4_PARSE_OPTIONS)(
EFI_MTFTP4_PROTOCOL *This,
UINT32 PacketLen,
EFI_MTFTP4_PACKET *Packet,
UINT32 *OptionCount,
EFI_MTFTP4_OPTION **OptionList
);
typedef
EFI_STATUS
( *EFI_MTFTP4_READ_FILE)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP4_WRITE_FILE)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP4_READ_DIRECTORY)(
EFI_MTFTP4_PROTOCOL *This,
EFI_MTFTP4_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP4_POLL)(
EFI_MTFTP4_PROTOCOL *This
);

struct _EFI_MTFTP4_PROTOCOL {
EFI_MTFTP4_GET_MODE_DATA GetModeData;
EFI_MTFTP4_CONFIGURE Configure;
EFI_MTFTP4_GET_INFO GetInfo;
EFI_MTFTP4_PARSE_OPTIONS ParseOptions;
EFI_MTFTP4_READ_FILE ReadFile;
EFI_MTFTP4_WRITE_FILE WriteFile;
EFI_MTFTP4_READ_DIRECTORY ReadDirectory;
EFI_MTFTP4_POLL Poll;
};

struct _EFI_MTFTP4_TOKEN {

EFI_STATUS Status;

EFI_EVENT Event;

EFI_MTFTP4_OVERRIDE_DATA *OverrideData;

UINT8 *Filename;

UINT8 *ModeStr;

UINT32 OptionCount;

EFI_MTFTP4_OPTION *OptionList;

UINT64 BufferSize;

void *Buffer;

void *Context;

EFI_MTFTP4_CHECK_PACKET CheckPacket;

EFI_MTFTP4_TIMEOUT_CALLBACK TimeoutCallback;

EFI_MTFTP4_PACKET_NEEDED PacketNeeded;
};

extern EFI_GUID gEfiMtftp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiMtftp4ProtocolGuid;
typedef struct _EFI_MTFTP6_PROTOCOL EFI_MTFTP6_PROTOCOL;
typedef struct _EFI_MTFTP6_TOKEN EFI_MTFTP6_TOKEN;
#pragma pack(1)

typedef struct {

UINT16 OpCode;

UINT8 Filename[1];
} EFI_MTFTP6_REQ_HEADER;

typedef struct {

UINT16 OpCode;

UINT8 Data[1];
} EFI_MTFTP6_OACK_HEADER;

typedef struct {

UINT16 OpCode;

UINT16 Block;

UINT8 Data[1];
} EFI_MTFTP6_DATA_HEADER;

typedef struct {

UINT16 OpCode;

UINT16 Block[1];
} EFI_MTFTP6_ACK_HEADER;

typedef struct {

UINT16 OpCode;

UINT64 Block;

UINT8 Data[1];
} EFI_MTFTP6_DATA8_HEADER;

typedef struct {

UINT16 OpCode;

UINT64 Block[1];
} EFI_MTFTP6_ACK8_HEADER;

typedef struct {

UINT16 OpCode;

UINT16 ErrorCode;

UINT8 ErrorMessage[1];
} EFI_MTFTP6_ERROR_HEADER;

typedef union {
UINT16 OpCode;
EFI_MTFTP6_REQ_HEADER Rrq;
EFI_MTFTP6_REQ_HEADER Wrq;
EFI_MTFTP6_OACK_HEADER Oack;
EFI_MTFTP6_DATA_HEADER Data;
EFI_MTFTP6_ACK_HEADER Ack;
EFI_MTFTP6_DATA8_HEADER Data8;
EFI_MTFTP6_ACK8_HEADER Ack8;
EFI_MTFTP6_ERROR_HEADER Error;
} EFI_MTFTP6_PACKET;

#pragma pack()

typedef struct {

EFI_IPv6_ADDRESS StationIp;

UINT16 LocalPort;

EFI_IPv6_ADDRESS ServerIp;

UINT16 InitialServerPort;

UINT16 TryCount;

UINT16 TimeoutValue;
} EFI_MTFTP6_CONFIG_DATA;

typedef struct {

EFI_MTFTP6_CONFIG_DATA ConfigData;

UINT8 SupportedOptionCount;

UINT8 **SupportedOptions;
} EFI_MTFTP6_MODE_DATA;

typedef struct {

EFI_IPv6_ADDRESS ServerIp;

UINT16 ServerPort;

UINT16 TryCount;

UINT16 TimeoutValue;
} EFI_MTFTP6_OVERRIDE_DATA;

typedef struct {
UINT8 *OptionStr;
UINT8 *ValueStr;
} EFI_MTFTP6_OPTION;
typedef
EFI_STATUS
( *EFI_MTFTP6_CHECK_PACKET)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token,
UINT16 PacketLen,
EFI_MTFTP6_PACKET *Packet
);
typedef
EFI_STATUS
( *EFI_MTFTP6_TIMEOUT_CALLBACK)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP6_PACKET_NEEDED)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token,
UINT16 *Length,
void **Buffer
);

struct _EFI_MTFTP6_TOKEN {

EFI_STATUS Status;

EFI_EVENT Event;

EFI_MTFTP6_OVERRIDE_DATA *OverrideData;

UINT8 *Filename;

UINT8 *ModeStr;

UINT32 OptionCount;

EFI_MTFTP6_OPTION *OptionList;

UINT64 BufferSize;

void *Buffer;

void *Context;

EFI_MTFTP6_CHECK_PACKET CheckPacket;

EFI_MTFTP6_TIMEOUT_CALLBACK TimeoutCallback;

EFI_MTFTP6_PACKET_NEEDED PacketNeeded;
};
typedef
EFI_STATUS
( *EFI_MTFTP6_GET_MODE_DATA)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_MODE_DATA *ModeData
);
typedef
EFI_STATUS
( *EFI_MTFTP6_CONFIGURE)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_CONFIG_DATA *MtftpConfigData
);
typedef
EFI_STATUS
( *EFI_MTFTP6_GET_INFO)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_OVERRIDE_DATA *OverrideData ,
UINT8 *Filename,
UINT8 *ModeStr ,
UINT8 OptionCount,
EFI_MTFTP6_OPTION *OptionList ,
UINT32 *PacketLength,
EFI_MTFTP6_PACKET **Packet
);
typedef
EFI_STATUS
( *EFI_MTFTP6_PARSE_OPTIONS)(
EFI_MTFTP6_PROTOCOL *This,
UINT32 PacketLen,
EFI_MTFTP6_PACKET *Packet,
UINT32 *OptionCount,
EFI_MTFTP6_OPTION **OptionList
);
typedef
EFI_STATUS
( *EFI_MTFTP6_READ_FILE)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP6_WRITE_FILE)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP6_READ_DIRECTORY)(
EFI_MTFTP6_PROTOCOL *This,
EFI_MTFTP6_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_MTFTP6_POLL)(
EFI_MTFTP6_PROTOCOL *This
);

struct _EFI_MTFTP6_PROTOCOL {
EFI_MTFTP6_GET_MODE_DATA GetModeData;
EFI_MTFTP6_CONFIGURE Configure;
EFI_MTFTP6_GET_INFO GetInfo;
EFI_MTFTP6_PARSE_OPTIONS ParseOptions;
EFI_MTFTP6_READ_FILE ReadFile;
EFI_MTFTP6_WRITE_FILE WriteFile;
EFI_MTFTP6_READ_DIRECTORY ReadDirectory;
EFI_MTFTP6_POLL Poll;
};

extern EFI_GUID gEfiMtftp6ServiceBindingProtocolGuid;
extern EFI_GUID gEfiMtftp6ProtocolGuid;
typedef struct _EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL;

typedef EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL EFI_NETWORK_INTERFACE_IDENTIFIER_INTERFACE;

struct _EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL {
UINT64 Revision;
UINT64 Id;

UINT64 ImageAddr;

UINT32 ImageSize;
CHAR8 StringId[4];

UINT8 Type;

UINT8 MajorVer;
UINT8 MinorVer;
BOOLEAN Ipv6Supported;
UINT8 IfNum;

};

typedef enum {
EfiNetworkInterfaceUndi = 1
} EFI_NETWORK_INTERFACE_TYPE;

typedef struct undiconfig_table UNDI_CONFIG_TABLE;

struct undiconfig_table {
UINT32 NumberOfInterfaces;

UINT32 reserved;
UNDI_CONFIG_TABLE *nextlink;

struct {
void *NII_InterfacePointer;
void *DevicePathPointer;
} NII_entry[1];
};

extern EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid;
extern EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid_31;
extern EFI_GUID gPcdProtocolGuid;
typedef
void
( *PCD_PROTOCOL_SET_SKU)(
UINTN SkuId
);
typedef
UINT8
( *PCD_PROTOCOL_GET8)(
UINTN TokenNumber
);
typedef
UINT16
( *PCD_PROTOCOL_GET16)(
UINTN TokenNumber
);
typedef
UINT32
( *PCD_PROTOCOL_GET32)(
UINTN TokenNumber
);
typedef
UINT64
( *PCD_PROTOCOL_GET64)(
UINTN TokenNumber
);
typedef
void *
( *PCD_PROTOCOL_GET_POINTER)(
UINTN TokenNumber
);
typedef
BOOLEAN
( *PCD_PROTOCOL_GET_BOOLEAN)(
UINTN TokenNumber
);
typedef
UINTN
( *PCD_PROTOCOL_GET_SIZE)(
UINTN TokenNumber
);
typedef
UINT8
( *PCD_PROTOCOL_GET_EX_8)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT16
( *PCD_PROTOCOL_GET_EX_16)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT32
( *PCD_PROTOCOL_GET_EX_32)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT64
( *PCD_PROTOCOL_GET_EX_64)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
void *
( *PCD_PROTOCOL_GET_EX_POINTER)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
BOOLEAN
( *PCD_PROTOCOL_GET_EX_BOOLEAN)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINTN
( *PCD_PROTOCOL_GET_EX_SIZE)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET8)(
UINTN TokenNumber,
UINT8 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET16)(
UINTN TokenNumber,
UINT16 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET32)(
UINTN TokenNumber,
UINT32 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET64)(
UINTN TokenNumber,
UINT64 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_POINTER)(
UINTN TokenNumber,
UINTN *SizeOfBuffer,
void *Buffer
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_BOOLEAN)(
UINTN TokenNumber,
BOOLEAN Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_8)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT8 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_16)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT16 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_32)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT32 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_64)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT64 Value
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_POINTER)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINTN *SizeOfBuffer,
void *Buffer
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_SET_EX_BOOLEAN)(
EFI_GUID *Guid,
UINTN TokenNumber,
BOOLEAN Value
);
typedef
void
( *PCD_PROTOCOL_CALLBACK)(
EFI_GUID *CallBackGuid,
UINTN CallBackToken,
void *TokenData,
UINTN TokenDataSize
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_CALLBACK_ONSET)(
EFI_GUID *Guid,
UINTN TokenNumber,
PCD_PROTOCOL_CALLBACK CallBackFunction
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_CANCEL_CALLBACK)(
EFI_GUID *Guid,
UINTN TokenNumber,
PCD_PROTOCOL_CALLBACK CallBackFunction
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_GET_NEXT_TOKEN)(
EFI_GUID *Guid,
UINTN *TokenNumber
);
typedef
EFI_STATUS
( *PCD_PROTOCOL_GET_NEXT_TOKENSPACE)(
EFI_GUID **Guid
);

typedef struct {
PCD_PROTOCOL_SET_SKU SetSku;

PCD_PROTOCOL_GET8 Get8;
PCD_PROTOCOL_GET16 Get16;
PCD_PROTOCOL_GET32 Get32;
PCD_PROTOCOL_GET64 Get64;
PCD_PROTOCOL_GET_POINTER GetPtr;
PCD_PROTOCOL_GET_BOOLEAN GetBool;
PCD_PROTOCOL_GET_SIZE GetSize;

PCD_PROTOCOL_GET_EX_8 Get8Ex;
PCD_PROTOCOL_GET_EX_16 Get16Ex;
PCD_PROTOCOL_GET_EX_32 Get32Ex;
PCD_PROTOCOL_GET_EX_64 Get64Ex;
PCD_PROTOCOL_GET_EX_POINTER GetPtrEx;
PCD_PROTOCOL_GET_EX_BOOLEAN GetBoolEx;
PCD_PROTOCOL_GET_EX_SIZE GetSizeEx;

PCD_PROTOCOL_SET8 Set8;
PCD_PROTOCOL_SET16 Set16;
PCD_PROTOCOL_SET32 Set32;
PCD_PROTOCOL_SET64 Set64;
PCD_PROTOCOL_SET_POINTER SetPtr;
PCD_PROTOCOL_SET_BOOLEAN SetBool;

PCD_PROTOCOL_SET_EX_8 Set8Ex;
PCD_PROTOCOL_SET_EX_16 Set16Ex;
PCD_PROTOCOL_SET_EX_32 Set32Ex;
PCD_PROTOCOL_SET_EX_64 Set64Ex;
PCD_PROTOCOL_SET_EX_POINTER SetPtrEx;
PCD_PROTOCOL_SET_EX_BOOLEAN SetBoolEx;

PCD_PROTOCOL_CALLBACK_ONSET CallbackOnSet;
PCD_PROTOCOL_CANCEL_CALLBACK CancelCallback;
PCD_PROTOCOL_GET_NEXT_TOKEN GetNextToken;
PCD_PROTOCOL_GET_NEXT_TOKENSPACE GetNextTokenSpace;
} PCD_PROTOCOL;
extern EFI_GUID gEfiPciEnumerationCompleteProtocolGuid;
typedef struct _EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL;

typedef enum {
EfiPciWidthUint8,
EfiPciWidthUint16,
EfiPciWidthUint32,
EfiPciWidthUint64,
EfiPciWidthFifoUint8,
EfiPciWidthFifoUint16,
EfiPciWidthFifoUint32,
EfiPciWidthFifoUint64,
EfiPciWidthFillUint8,
EfiPciWidthFillUint16,
EfiPciWidthFillUint32,
EfiPciWidthFillUint64,
EfiPciWidthMaximum
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH;

typedef enum {

EfiPciOperationBusMasterRead,

EfiPciOperationBusMasterWrite,

EfiPciOperationBusMasterCommonBuffer,

EfiPciOperationBusMasterRead64,

EfiPciOperationBusMasterWrite64,

EfiPciOperationBusMasterCommonBuffer64,
EfiPciOperationMaximum
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION;
typedef struct {
UINT8 Register;
UINT8 Function;
UINT8 Device;
UINT8 Bus;
UINT32 ExtendedRegister;
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS;
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_POLL_IO_MEM)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH Width,
UINT64 Address,
UINT64 Mask,
UINT64 Value,
UINT64 Delay,
UINT64 *Result
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_IO_MEM)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH Width,
UINT64 Address,
UINTN Count,
void *Buffer
);

typedef struct {

EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_IO_MEM Read;

EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_IO_MEM Write;
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ACCESS;
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_COPY_MEM)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH Width,
UINT64 DestAddress,
UINT64 SrcAddress,
UINTN Count
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_MAP)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION Operation,
void *HostAddress,
UINTN *NumberOfBytes,
EFI_PHYSICAL_ADDRESS *DeviceAddress,
void **Mapping
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_UNMAP)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
void *Mapping
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ALLOCATE_BUFFER)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
EFI_ALLOCATE_TYPE Type,
EFI_MEMORY_TYPE MemoryType,
UINTN Pages,
void **HostAddress,
UINT64 Attributes
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_FREE_BUFFER)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
UINTN Pages,
void *HostAddress
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_FLUSH)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GET_ATTRIBUTES)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
UINT64 *Supports,
UINT64 *Attributes
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_SET_ATTRIBUTES)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
UINT64 Attributes,
UINT64 *ResourceBase,
UINT64 *ResourceLength
);
typedef
EFI_STATUS
( *EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_CONFIGURATION)(
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *This,
void **Resources
);

struct _EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL {

EFI_HANDLE ParentHandle;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_POLL_IO_MEM PollMem;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_POLL_IO_MEM PollIo;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ACCESS Mem;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ACCESS Io;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ACCESS Pci;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_COPY_MEM CopyMem;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_MAP Map;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_UNMAP Unmap;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_ALLOCATE_BUFFER AllocateBuffer;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_FREE_BUFFER FreeBuffer;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_FLUSH Flush;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GET_ATTRIBUTES GetAttributes;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_SET_ATTRIBUTES SetAttributes;
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_CONFIGURATION Configuration;

UINT32 SegmentNumber;
};

extern EFI_GUID gEfiPciRootBridgeIoProtocolGuid;
typedef struct _EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL;
typedef UINT64 EFI_RESOURCE_ALLOCATION_STATUS;
typedef enum {

EfiPciHostBridgeBeginEnumeration,

EfiPciHostBridgeBeginBusAllocation,

EfiPciHostBridgeEndBusAllocation,

EfiPciHostBridgeBeginResourceAllocation,

EfiPciHostBridgeAllocateResources,

EfiPciHostBridgeSetResources,

EfiPciHostBridgeFreeResources,

EfiPciHostBridgeEndResourceAllocation,

EfiPciHostBridgeEndEnumeration,
EfiMaxPciHostBridgeEnumerationPhase
} EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE;

typedef enum {
EfiPciBeforeChildBusEnumeration,

EfiPciBeforeResourceCollection
} EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE;
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_NOTIFY_PHASE)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE Phase
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_NEXT_ROOT_BRIDGE)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE *RootBridgeHandle
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_ATTRIBUTES)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
UINT64 *Attributes
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_START_BUS_ENUMERATION)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
void **Configuration
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_SET_BUS_NUMBERS)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
void *Configuration
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_SUBMIT_RESOURCES)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
void *Configuration
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_PROPOSED_RESOURCES)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
void **Configuration
);
typedef
EFI_STATUS
( *EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_PREPROCESS_CONTROLLER)(
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
EFI_HANDLE RootBridgeHandle,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS PciAddress,
EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE Phase
);

struct _EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL {

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_NOTIFY_PHASE NotifyPhase;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_NEXT_ROOT_BRIDGE GetNextRootBridge;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_ATTRIBUTES GetAllocAttributes;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_START_BUS_ENUMERATION StartBusEnumeration;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_SET_BUS_NUMBERS SetBusNumbers;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_SUBMIT_RESOURCES SubmitResources;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_GET_PROPOSED_RESOURCES GetProposedResources;

EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_PREPROCESS_CONTROLLER PreprocessController;
};

extern EFI_GUID gEfiPciHostBridgeResourceAllocationProtocolGuid;
typedef struct _EFI_PCI_HOT_PLUG_INIT_PROTOCOL EFI_PCI_HOT_PLUG_INIT_PROTOCOL;

typedef UINT16 EFI_HPC_STATE;
typedef struct{

EFI_DEVICE_PATH_PROTOCOL *HpcDevicePath;

EFI_DEVICE_PATH_PROTOCOL *HpbDevicePath;
} EFI_HPC_LOCATION;

typedef enum {

EfiPaddingPciBus,
EfiPaddingPciRootBridge
} EFI_HPC_PADDING_ATTRIBUTES;
typedef
EFI_STATUS
( *EFI_GET_ROOT_HPC_LIST)(
EFI_PCI_HOT_PLUG_INIT_PROTOCOL *This,
UINTN *HpcCount,
EFI_HPC_LOCATION **HpcList
);
typedef
EFI_STATUS
( *EFI_INITIALIZE_ROOT_HPC)(
EFI_PCI_HOT_PLUG_INIT_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *HpcDevicePath,
UINT64 HpcPciAddress,
EFI_EVENT Event,
EFI_HPC_STATE *HpcState
);
typedef
EFI_STATUS
( *EFI_GET_HOT_PLUG_PADDING)(
EFI_PCI_HOT_PLUG_INIT_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *HpcDevicePath,
UINT64 HpcPciAddress,
EFI_HPC_STATE *HpcState,
void **Padding,
EFI_HPC_PADDING_ATTRIBUTES *Attributes
);

struct _EFI_PCI_HOT_PLUG_INIT_PROTOCOL {

EFI_GET_ROOT_HPC_LIST GetRootHpcList;

EFI_INITIALIZE_ROOT_HPC InitializeRootHpc;

EFI_GET_HOT_PLUG_PADDING GetResourcePadding;
};

extern EFI_GUID gEfiPciHotPlugInitProtocolGuid;
typedef struct _EFI_PCI_HOTPLUG_REQUEST_PROTOCOL EFI_PCI_HOTPLUG_REQUEST_PROTOCOL;

typedef enum {

EfiPciHotPlugRequestAdd,

EfiPciHotplugRequestRemove
} EFI_PCI_HOTPLUG_OPERATION;
typedef
EFI_STATUS
( *EFI_PCI_HOTPLUG_REQUEST_NOTIFY)(
EFI_PCI_HOTPLUG_REQUEST_PROTOCOL *This,
EFI_PCI_HOTPLUG_OPERATION Operation,
EFI_HANDLE Controller,
EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath ,
UINT8 *NumberOfChildren,
EFI_HANDLE *ChildHandleBuffer
);

struct _EFI_PCI_HOTPLUG_REQUEST_PROTOCOL {

EFI_PCI_HOTPLUG_REQUEST_NOTIFY Notify;
};

extern EFI_GUID gEfiPciHotPlugRequestProtocolGuid;
typedef struct _EFI_PCI_IO_PROTOCOL EFI_PCI_IO_PROTOCOL;

typedef enum {
EfiPciIoWidthUint8 = 0,
EfiPciIoWidthUint16,
EfiPciIoWidthUint32,
EfiPciIoWidthUint64,
EfiPciIoWidthFifoUint8,
EfiPciIoWidthFifoUint16,
EfiPciIoWidthFifoUint32,
EfiPciIoWidthFifoUint64,
EfiPciIoWidthFillUint8,
EfiPciIoWidthFillUint16,
EfiPciIoWidthFillUint32,
EfiPciIoWidthFillUint64,
EfiPciIoWidthMaximum
} EFI_PCI_IO_PROTOCOL_WIDTH;
typedef enum {

EfiPciIoOperationBusMasterRead,

EfiPciIoOperationBusMasterWrite,

EfiPciIoOperationBusMasterCommonBuffer,
EfiPciIoOperationMaximum
} EFI_PCI_IO_PROTOCOL_OPERATION;

typedef enum {

EfiPciIoAttributeOperationGet,

EfiPciIoAttributeOperationSet,

EfiPciIoAttributeOperationEnable,

EfiPciIoAttributeOperationDisable,

EfiPciIoAttributeOperationSupported,
EfiPciIoAttributeOperationMaximum
} EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION;
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_POLL_IO_MEM)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_WIDTH Width,
UINT8 BarIndex,
UINT64 Offset,
UINT64 Mask,
UINT64 Value,
UINT64 Delay,
UINT64 *Result
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_IO_MEM)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_WIDTH Width,
UINT8 BarIndex,
UINT64 Offset,
UINTN Count,
void *Buffer
);

typedef struct {

EFI_PCI_IO_PROTOCOL_IO_MEM Read;

EFI_PCI_IO_PROTOCOL_IO_MEM Write;
} EFI_PCI_IO_PROTOCOL_ACCESS;
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_CONFIG)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_WIDTH Width,
UINT32 Offset,
UINTN Count,
void *Buffer
);

typedef struct {

EFI_PCI_IO_PROTOCOL_CONFIG Read;

EFI_PCI_IO_PROTOCOL_CONFIG Write;
} EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS;
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_COPY_MEM)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_WIDTH Width,
UINT8 DestBarIndex,
UINT64 DestOffset,
UINT8 SrcBarIndex,
UINT64 SrcOffset,
UINTN Count
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_MAP)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_OPERATION Operation,
void *HostAddress,
UINTN *NumberOfBytes,
EFI_PHYSICAL_ADDRESS *DeviceAddress,
void **Mapping
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_UNMAP)(
EFI_PCI_IO_PROTOCOL *This,
void *Mapping
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER)(
EFI_PCI_IO_PROTOCOL *This,
EFI_ALLOCATE_TYPE Type,
EFI_MEMORY_TYPE MemoryType,
UINTN Pages,
void **HostAddress,
UINT64 Attributes
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_FREE_BUFFER)(
EFI_PCI_IO_PROTOCOL *This,
UINTN Pages,
void *HostAddress
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_FLUSH)(
EFI_PCI_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_GET_LOCATION)(
EFI_PCI_IO_PROTOCOL *This,
UINTN *SegmentNumber,
UINTN *BusNumber,
UINTN *DeviceNumber,
UINTN *FunctionNumber
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_ATTRIBUTES)(
EFI_PCI_IO_PROTOCOL *This,
EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION Operation,
UINT64 Attributes,
UINT64 *Result
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES)(
EFI_PCI_IO_PROTOCOL *This,
UINT8 BarIndex,
UINT64 *Supports,
void **Resources
);
typedef
EFI_STATUS
( *EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES)(
EFI_PCI_IO_PROTOCOL *This,
UINT64 Attributes,
UINT8 BarIndex,
UINT64 *Offset,
UINT64 *Length
);
struct _EFI_PCI_IO_PROTOCOL {
EFI_PCI_IO_PROTOCOL_POLL_IO_MEM PollMem;
EFI_PCI_IO_PROTOCOL_POLL_IO_MEM PollIo;
EFI_PCI_IO_PROTOCOL_ACCESS Mem;
EFI_PCI_IO_PROTOCOL_ACCESS Io;
EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS Pci;
EFI_PCI_IO_PROTOCOL_COPY_MEM CopyMem;
EFI_PCI_IO_PROTOCOL_MAP Map;
EFI_PCI_IO_PROTOCOL_UNMAP Unmap;
EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER AllocateBuffer;
EFI_PCI_IO_PROTOCOL_FREE_BUFFER FreeBuffer;
EFI_PCI_IO_PROTOCOL_FLUSH Flush;
EFI_PCI_IO_PROTOCOL_GET_LOCATION GetLocation;
EFI_PCI_IO_PROTOCOL_ATTRIBUTES Attributes;
EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES GetBarAttributes;
EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES SetBarAttributes;

UINT64 RomSize;
void *RomImage;
};

extern EFI_GUID gEfiPciIoProtocolGuid;
typedef struct _EFI_PCI_PLATFORM_PROTOCOL EFI_PCI_PLATFORM_PROTOCOL;
typedef UINT32 EFI_PCI_PLATFORM_POLICY;
typedef enum {

BeforePciHostBridge = 0,

ChipsetEntry = 0,

AfterPciHostBridge = 1,

ChipsetExit = 1,
MaximumChipsetPhase
} EFI_PCI_EXECUTION_PHASE;

typedef EFI_PCI_EXECUTION_PHASE EFI_PCI_CHIPSET_EXECUTION_PHASE;
typedef
EFI_STATUS
( *EFI_PCI_PLATFORM_PHASE_NOTIFY)(
EFI_PCI_PLATFORM_PROTOCOL *This,
EFI_HANDLE HostBridge,
EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE Phase,
EFI_PCI_EXECUTION_PHASE ExecPhase
);
typedef
EFI_STATUS
( *EFI_PCI_PLATFORM_PREPROCESS_CONTROLLER)(
EFI_PCI_PLATFORM_PROTOCOL *This,
EFI_HANDLE HostBridge,
EFI_HANDLE RootBridge,
EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS PciAddress,
EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE Phase,
EFI_PCI_EXECUTION_PHASE ExecPhase
);
typedef
EFI_STATUS
( *EFI_PCI_PLATFORM_GET_PLATFORM_POLICY)(
EFI_PCI_PLATFORM_PROTOCOL *This,
EFI_PCI_PLATFORM_POLICY *PciPolicy
);
typedef
EFI_STATUS
( *EFI_PCI_PLATFORM_GET_PCI_ROM)(
EFI_PCI_PLATFORM_PROTOCOL *This,
EFI_HANDLE PciHandle,
void **RomImage,
UINTN *RomSize
);

struct _EFI_PCI_PLATFORM_PROTOCOL {

EFI_PCI_PLATFORM_PHASE_NOTIFY PlatformNotify;

EFI_PCI_PLATFORM_PREPROCESS_CONTROLLER PlatformPrepController;

EFI_PCI_PLATFORM_GET_PLATFORM_POLICY GetPlatformPolicy;

EFI_PCI_PLATFORM_GET_PCI_ROM GetPciRom;
};

extern EFI_GUID gEfiPciPlatformProtocolGuid;
typedef EFI_PCI_PLATFORM_PROTOCOL EFI_PCI_OVERRIDE_PROTOCOL;

extern EFI_GUID gEfiPciOverrideProtocolGuid;

extern EFI_GUID gEfiPcdProtocolGuid;
typedef
void
( *EFI_PCD_PROTOCOL_SET_SKU)(
UINTN SkuId
);
typedef
UINT8
( *EFI_PCD_PROTOCOL_GET_8)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT16
( *EFI_PCD_PROTOCOL_GET_16)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT32
( *EFI_PCD_PROTOCOL_GET_32)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINT64
( *EFI_PCD_PROTOCOL_GET_64)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
void *
( *EFI_PCD_PROTOCOL_GET_POINTER)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
BOOLEAN
( *EFI_PCD_PROTOCOL_GET_BOOLEAN)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
UINTN
( *EFI_PCD_PROTOCOL_GET_SIZE)(
EFI_GUID *Guid,
UINTN TokenNumber
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_8)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT8 Value
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_16)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT16 Value
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_32)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT32 Value
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_64)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINT64 Value
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_POINTER)(
EFI_GUID *Guid,
UINTN TokenNumber,
UINTN *SizeOfValue,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_SET_BOOLEAN)(
EFI_GUID *Guid,
UINTN TokenNumber,
BOOLEAN Value
);

typedef
void
( *EFI_PCD_PROTOCOL_CALLBACK)(
EFI_GUID *Guid ,
UINTN CallBackToken,
void *TokenData,
UINTN TokenDataSize
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_CALLBACK_ON_SET)(
EFI_GUID *Guid ,
UINTN CallBackToken,
EFI_PCD_PROTOCOL_CALLBACK CallBackFunction
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_CANCEL_CALLBACK)(
EFI_GUID *Guid ,
UINTN CallBackToken,
EFI_PCD_PROTOCOL_CALLBACK CallBackFunction
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_GET_NEXT_TOKEN)(
EFI_GUID *Guid,
UINTN *TokenNumber
);
typedef
EFI_STATUS
( *EFI_PCD_PROTOCOL_GET_NEXT_TOKEN_SPACE)(
EFI_GUID **Guid
);

typedef struct _EFI_PCD_PROTOCOL {
EFI_PCD_PROTOCOL_SET_SKU SetSku;
EFI_PCD_PROTOCOL_GET_8 Get8;
EFI_PCD_PROTOCOL_GET_16 Get16;
EFI_PCD_PROTOCOL_GET_32 Get32;
EFI_PCD_PROTOCOL_GET_64 Get64;
EFI_PCD_PROTOCOL_GET_POINTER GetPtr;
EFI_PCD_PROTOCOL_GET_BOOLEAN GetBool;
EFI_PCD_PROTOCOL_GET_SIZE GetSize;
EFI_PCD_PROTOCOL_SET_8 Set8;
EFI_PCD_PROTOCOL_SET_16 Set16;
EFI_PCD_PROTOCOL_SET_32 Set32;
EFI_PCD_PROTOCOL_SET_64 Set64;
EFI_PCD_PROTOCOL_SET_POINTER SetPtr;
EFI_PCD_PROTOCOL_SET_BOOLEAN SetBool;
EFI_PCD_PROTOCOL_CALLBACK_ON_SET CallbackOnSet;
EFI_PCD_PROTOCOL_CANCEL_CALLBACK CancelCallback;
EFI_PCD_PROTOCOL_GET_NEXT_TOKEN GetNextToken;
EFI_PCD_PROTOCOL_GET_NEXT_TOKEN_SPACE GetNextTokenSpace;
} EFI_PCD_PROTOCOL;
typedef struct _EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_PLATFORM_DRIVER_OVERRIDE_GET_DRIVER)(
EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE *DriverImageHandle
);
typedef
EFI_STATUS
( *EFI_PLATFORM_DRIVER_OVERRIDE_GET_DRIVER_PATH)(
EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_DEVICE_PATH_PROTOCOL **DriverImagePath
);
typedef
EFI_STATUS
( *EFI_PLATFORM_DRIVER_OVERRIDE_DRIVER_LOADED)(
EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_DEVICE_PATH_PROTOCOL *DriverImagePath,
EFI_HANDLE DriverImageHandle
);
struct _EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL {
EFI_PLATFORM_DRIVER_OVERRIDE_GET_DRIVER GetDriver;
EFI_PLATFORM_DRIVER_OVERRIDE_GET_DRIVER_PATH GetDriverPath;
EFI_PLATFORM_DRIVER_OVERRIDE_DRIVER_LOADED DriverLoaded;
};

extern EFI_GUID gEfiPlatformDriverOverrideProtocolGuid;
typedef struct _EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL;
typedef
EFI_STATUS
( *EFI_PLATFORM_TO_DRIVER_CONFIGURATION_QUERY)(
EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
UINTN *Instance,
EFI_GUID **ParameterTypeGuid,
void **ParameterBlock,
UINTN *ParameterBlockSize
);

typedef enum {
EfiPlatformConfigurationActionNone = 0,
EfiPlatformConfigurationActionStopController = 1,
EfiPlatformConfigurationActionRestartController = 2,
EfiPlatformConfigurationActionRestartPlatform = 3,
EfiPlatformConfigurationActionNvramFailed = 4,
EfiPlatformConfigurationActionMaximum
} EFI_PLATFORM_CONFIGURATION_ACTION;
typedef
EFI_STATUS
( *EFI_PLATFORM_TO_DRIVER_CONFIGURATION_RESPONSE)(
EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL *This,
EFI_HANDLE ControllerHandle,
EFI_HANDLE ChildHandle ,
UINTN *Instance,
EFI_GUID *ParameterTypeGuid,
void *ParameterBlock,
UINTN ParameterBlockSize ,
EFI_PLATFORM_CONFIGURATION_ACTION ConfigurationAction
);
struct _EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL {
EFI_PLATFORM_TO_DRIVER_CONFIGURATION_QUERY Query;
EFI_PLATFORM_TO_DRIVER_CONFIGURATION_RESPONSE Response;
};
typedef struct {
CHAR8 *CLPCommand;

UINT32 CLPCommandLength;
CHAR8 *CLPReturnString;
UINT32 CLPReturnStringLength;
UINT8 CLPCmdStatus;

UINT8 CLPErrorValue;

UINT16 CLPMsgCode;

} EFI_CONFIGURE_CLP_PARAMETER_BLK;

extern EFI_GUID gEfiPlatformToDriverConfigurationClpGuid;

extern EFI_GUID gEfiPlatformToDriverConfigurationProtocolGuid;
typedef struct _EFI_PXE_BASE_CODE_PROTOCOL EFI_PXE_BASE_CODE_PROTOCOL;

typedef EFI_PXE_BASE_CODE_PROTOCOL EFI_PXE_BASE_CODE;
typedef struct {
UINT8 Type;
UINT8 Code;
UINT16 Checksum;
union {
UINT32 reserved;
UINT32 Mtu;
UINT32 Pointer;
struct {
UINT16 Identifier;
UINT16 Sequence;
} Echo;
} u;
UINT8 Data[494];
} EFI_PXE_BASE_CODE_ICMP_ERROR;

typedef struct {
UINT8 ErrorCode;
CHAR8 ErrorString[127];
} EFI_PXE_BASE_CODE_TFTP_ERROR;
typedef struct {
UINT8 Filters;
UINT8 IpCnt;
UINT16 reserved;
EFI_IP_ADDRESS IpList[8];
} EFI_PXE_BASE_CODE_IP_FILTER;
typedef struct {
EFI_IP_ADDRESS IpAddr;
EFI_MAC_ADDRESS MacAddr;
} EFI_PXE_BASE_CODE_ARP_ENTRY;

typedef struct {
EFI_IP_ADDRESS IpAddr;
EFI_IP_ADDRESS SubnetMask;
EFI_IP_ADDRESS GwAddr;
} EFI_PXE_BASE_CODE_ROUTE_ENTRY;

typedef UINT16 EFI_PXE_BASE_CODE_UDP_PORT;
typedef struct {
UINT16 Type;
BOOLEAN AcceptAnyResponse;
UINT8 Reserved;
EFI_IP_ADDRESS IpAddr;
} EFI_PXE_BASE_CODE_SRVLIST;

typedef struct {
BOOLEAN UseMCast;
BOOLEAN UseBCast;
BOOLEAN UseUCast;
BOOLEAN MustUseList;
EFI_IP_ADDRESS ServerMCastIp;
UINT16 IpCnt;
EFI_PXE_BASE_CODE_SRVLIST SrvList[1];
} EFI_PXE_BASE_CODE_DISCOVER_INFO;

typedef enum {
EFI_PXE_BASE_CODE_TFTP_FIRST,
EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE,
EFI_PXE_BASE_CODE_TFTP_READ_FILE,
EFI_PXE_BASE_CODE_TFTP_WRITE_FILE,
EFI_PXE_BASE_CODE_TFTP_READ_DIRECTORY,
EFI_PXE_BASE_CODE_MTFTP_GET_FILE_SIZE,
EFI_PXE_BASE_CODE_MTFTP_READ_FILE,
EFI_PXE_BASE_CODE_MTFTP_READ_DIRECTORY,
EFI_PXE_BASE_CODE_MTFTP_LAST
} EFI_PXE_BASE_CODE_TFTP_OPCODE;

typedef struct {
EFI_IP_ADDRESS MCastIp;
EFI_PXE_BASE_CODE_UDP_PORT CPort;
EFI_PXE_BASE_CODE_UDP_PORT SPort;
UINT16 ListenTimeout;
UINT16 TransmitTimeout;
} EFI_PXE_BASE_CODE_MTFTP_INFO;

typedef struct {
UINT8 BootpOpcode;
UINT8 BootpHwType;
UINT8 BootpHwAddrLen;
UINT8 BootpGateHops;
UINT32 BootpIdent;
UINT16 BootpSeconds;
UINT16 BootpFlags;
UINT8 BootpCiAddr[4];
UINT8 BootpYiAddr[4];
UINT8 BootpSiAddr[4];
UINT8 BootpGiAddr[4];
UINT8 BootpHwAddr[16];
UINT8 BootpSrvName[64];
UINT8 BootpBootFile[128];
UINT32 DhcpMagik;
UINT8 DhcpOptions[56];
} EFI_PXE_BASE_CODE_DHCPV4_PACKET;

typedef struct {
UINT32 MessageType:8;
UINT32 TransactionId:24;
UINT8 DhcpOptions[1024];
} EFI_PXE_BASE_CODE_DHCPV6_PACKET;

typedef union {
UINT8 Raw[1472];
EFI_PXE_BASE_CODE_DHCPV4_PACKET Dhcpv4;
EFI_PXE_BASE_CODE_DHCPV6_PACKET Dhcpv6;
} EFI_PXE_BASE_CODE_PACKET;
typedef struct {
BOOLEAN Started;
BOOLEAN Ipv6Available;
BOOLEAN Ipv6Supported;
BOOLEAN UsingIpv6;
BOOLEAN BisSupported;
BOOLEAN BisDetected;
BOOLEAN AutoArp;
BOOLEAN SendGUID;
BOOLEAN DhcpDiscoverValid;
BOOLEAN DhcpAckReceived;
BOOLEAN ProxyOfferReceived;
BOOLEAN PxeDiscoverValid;
BOOLEAN PxeReplyReceived;
BOOLEAN PxeBisReplyReceived;
BOOLEAN IcmpErrorReceived;
BOOLEAN TftpErrorReceived;
BOOLEAN MakeCallbacks;
UINT8 TTL;
UINT8 ToS;
EFI_IP_ADDRESS StationIp;
EFI_IP_ADDRESS SubnetMask;
EFI_PXE_BASE_CODE_PACKET DhcpDiscover;
EFI_PXE_BASE_CODE_PACKET DhcpAck;
EFI_PXE_BASE_CODE_PACKET ProxyOffer;
EFI_PXE_BASE_CODE_PACKET PxeDiscover;
EFI_PXE_BASE_CODE_PACKET PxeReply;
EFI_PXE_BASE_CODE_PACKET PxeBisReply;
EFI_PXE_BASE_CODE_IP_FILTER IpFilter;
UINT32 ArpCacheEntries;
EFI_PXE_BASE_CODE_ARP_ENTRY ArpCache[8];
UINT32 RouteTableEntries;
EFI_PXE_BASE_CODE_ROUTE_ENTRY RouteTable[8];
EFI_PXE_BASE_CODE_ICMP_ERROR IcmpError;
EFI_PXE_BASE_CODE_TFTP_ERROR TftpError;
} EFI_PXE_BASE_CODE_MODE;
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_START)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
BOOLEAN UseIpv6
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_STOP)(
EFI_PXE_BASE_CODE_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_DHCP)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
BOOLEAN SortOffers
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_DISCOVER)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
UINT16 Type,
UINT16 *Layer,
BOOLEAN UseBis,
EFI_PXE_BASE_CODE_DISCOVER_INFO *Info
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_MTFTP)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
EFI_PXE_BASE_CODE_TFTP_OPCODE Operation,
void *BufferPtr ,
BOOLEAN Overwrite,
UINT64 *BufferSize,
UINTN *BlockSize ,
EFI_IP_ADDRESS *ServerIp,
UINT8 *Filename ,
EFI_PXE_BASE_CODE_MTFTP_INFO *Info ,
BOOLEAN DontUseBuffer
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_UDP_WRITE)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
UINT16 OpFlags,
EFI_IP_ADDRESS *DestIp,
EFI_PXE_BASE_CODE_UDP_PORT *DestPort,
EFI_IP_ADDRESS *GatewayIp,
EFI_IP_ADDRESS *SrcIp,
EFI_PXE_BASE_CODE_UDP_PORT *SrcPort,
UINTN *HeaderSize,
void *HeaderPtr,
UINTN *BufferSize,
void *BufferPtr
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_UDP_READ)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
UINT16 OpFlags,
EFI_IP_ADDRESS *DestIp,
EFI_PXE_BASE_CODE_UDP_PORT *DestPort,
EFI_IP_ADDRESS *SrcIp,
EFI_PXE_BASE_CODE_UDP_PORT *SrcPort,
UINTN *HeaderSize,
void *HeaderPtr,
UINTN *BufferSize,
void *BufferPtr
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_SET_IP_FILTER)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
EFI_PXE_BASE_CODE_IP_FILTER *NewFilter
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_ARP)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
EFI_IP_ADDRESS *IpAddr,
EFI_MAC_ADDRESS *MacAddr
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_SET_PARAMETERS)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
BOOLEAN *NewAutoArp,
BOOLEAN *NewSendGUID,
UINT8 *NewTTL,
UINT8 *NewToS,
BOOLEAN *NewMakeCallback
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_SET_STATION_IP)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
EFI_IP_ADDRESS *NewStationIp,
EFI_IP_ADDRESS *NewSubnetMask
);
typedef
EFI_STATUS
( *EFI_PXE_BASE_CODE_SET_PACKETS)(
EFI_PXE_BASE_CODE_PROTOCOL *This,
BOOLEAN *NewDhcpDiscoverValid,
BOOLEAN *NewDhcpAckReceived,
BOOLEAN *NewProxyOfferReceived,
BOOLEAN *NewPxeDiscoverValid,
BOOLEAN *NewPxeReplyReceived,
BOOLEAN *NewPxeBisReplyReceived,
EFI_PXE_BASE_CODE_PACKET *NewDhcpDiscover,
EFI_PXE_BASE_CODE_PACKET *NewDhcpAck,
EFI_PXE_BASE_CODE_PACKET *NewProxyOffer,
EFI_PXE_BASE_CODE_PACKET *NewPxeDiscover,
EFI_PXE_BASE_CODE_PACKET *NewPxeReply,
EFI_PXE_BASE_CODE_PACKET *NewPxeBisReply
);
struct _EFI_PXE_BASE_CODE_PROTOCOL {

UINT64 Revision;
EFI_PXE_BASE_CODE_START Start;
EFI_PXE_BASE_CODE_STOP Stop;
EFI_PXE_BASE_CODE_DHCP Dhcp;
EFI_PXE_BASE_CODE_DISCOVER Discover;
EFI_PXE_BASE_CODE_MTFTP Mtftp;
EFI_PXE_BASE_CODE_UDP_WRITE UdpWrite;
EFI_PXE_BASE_CODE_UDP_READ UdpRead;
EFI_PXE_BASE_CODE_SET_IP_FILTER SetIpFilter;
EFI_PXE_BASE_CODE_ARP Arp;
EFI_PXE_BASE_CODE_SET_PARAMETERS SetParameters;
EFI_PXE_BASE_CODE_SET_STATION_IP SetStationIp;
EFI_PXE_BASE_CODE_SET_PACKETS SetPackets;

EFI_PXE_BASE_CODE_MODE *Mode;
};

extern EFI_GUID gEfiPxeBaseCodeProtocolGuid;
typedef struct _EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL;

typedef EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL EFI_PXE_BASE_CODE_CALLBACK;

typedef enum {
EFI_PXE_BASE_CODE_FUNCTION_FIRST,
EFI_PXE_BASE_CODE_FUNCTION_DHCP,
EFI_PXE_BASE_CODE_FUNCTION_DISCOVER,
EFI_PXE_BASE_CODE_FUNCTION_MTFTP,
EFI_PXE_BASE_CODE_FUNCTION_UDP_WRITE,
EFI_PXE_BASE_CODE_FUNCTION_UDP_READ,
EFI_PXE_BASE_CODE_FUNCTION_ARP,
EFI_PXE_BASE_CODE_FUNCTION_IGMP,
EFI_PXE_BASE_CODE_PXE_FUNCTION_LAST
} EFI_PXE_BASE_CODE_FUNCTION;

typedef enum {
EFI_PXE_BASE_CODE_CALLBACK_STATUS_FIRST,
EFI_PXE_BASE_CODE_CALLBACK_STATUS_CONTINUE,
EFI_PXE_BASE_CODE_CALLBACK_STATUS_ABORT,
EFI_PXE_BASE_CODE_CALLBACK_STATUS_LAST
} EFI_PXE_BASE_CODE_CALLBACK_STATUS;
typedef
EFI_PXE_BASE_CODE_CALLBACK_STATUS
( *EFI_PXE_CALLBACK)(
EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL *This,
EFI_PXE_BASE_CODE_FUNCTION Function,
BOOLEAN Received,
UINT32 PacketLen,
EFI_PXE_BASE_CODE_PACKET *Packet
);

struct _EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL {

UINT64 Revision;
EFI_PXE_CALLBACK Callback;
};

extern EFI_GUID gEfiPxeBaseCodeCallbackProtocolGuid;
extern EFI_GUID gEfiRealTimeClockArchProtocolGuid;
typedef
EFI_STATUS
( *EFI_RSC_HANDLER_CALLBACK)(
EFI_STATUS_CODE_TYPE CodeType,
EFI_STATUS_CODE_VALUE Value,
UINT32 Instance,
EFI_GUID *CallerId,
EFI_STATUS_CODE_DATA *Data
);
typedef
EFI_STATUS
( *EFI_RSC_HANDLER_REGISTER)(
EFI_RSC_HANDLER_CALLBACK Callback,
EFI_TPL Tpl
);
typedef
EFI_STATUS
( *EFI_RSC_HANDLER_UNREGISTER)(
EFI_RSC_HANDLER_CALLBACK Callback
);

typedef struct {
EFI_RSC_HANDLER_REGISTER Register;
EFI_RSC_HANDLER_UNREGISTER Unregister;
} EFI_RSC_HANDLER_PROTOCOL;

extern EFI_GUID gEfiRscHandlerProtocolGuid;
extern EFI_GUID gEfiResetArchProtocolGuid;
typedef struct _EFI_RUNTIME_ARCH_PROTOCOL EFI_RUNTIME_ARCH_PROTOCOL;

typedef LIST_ENTRY EFI_LIST_ENTRY;

typedef struct _EFI_RUNTIME_IMAGE_ENTRY EFI_RUNTIME_IMAGE_ENTRY;

struct _EFI_RUNTIME_IMAGE_ENTRY {

void *ImageBase;

UINT64 ImageSize;

void *RelocationData;

EFI_HANDLE Handle;

EFI_LIST_ENTRY Link;
};

typedef struct _EFI_RUNTIME_EVENT_ENTRY EFI_RUNTIME_EVENT_ENTRY;

struct _EFI_RUNTIME_EVENT_ENTRY {

UINT32 Type;

EFI_TPL NotifyTpl;

EFI_EVENT_NOTIFY NotifyFunction;

void *NotifyContext;

EFI_EVENT *Event;

EFI_LIST_ENTRY Link;
};
struct _EFI_RUNTIME_ARCH_PROTOCOL {
EFI_LIST_ENTRY ImageHead;
EFI_LIST_ENTRY EventHead;
UINTN MemoryDescriptorSize;
UINT32 MemoryDesciptorVersion;
UINTN MemoryMapSize;
EFI_MEMORY_DESCRIPTOR *MemoryMapPhysical;

EFI_MEMORY_DESCRIPTOR *MemoryMapVirtual;
BOOLEAN VirtualMode;
BOOLEAN AtRuntime;
};

extern EFI_GUID gEfiRuntimeArchProtocolGuid;
typedef void *EFI_S3_BOOT_SCRIPT_POSITION;

typedef struct _EFI_S3_SAVE_STATE_PROTOCOL EFI_S3_SAVE_STATE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_S3_SAVE_STATE_WRITE)(
EFI_S3_SAVE_STATE_PROTOCOL *This,
UINT16 OpCode,
...
);
typedef
EFI_STATUS
( *EFI_S3_SAVE_STATE_INSERT)(
EFI_S3_SAVE_STATE_PROTOCOL *This,
BOOLEAN BeforeOrAfter,
EFI_S3_BOOT_SCRIPT_POSITION *Position ,
UINT16 OpCode,
...
);
typedef
EFI_STATUS
( *EFI_S3_SAVE_STATE_LABEL)(
EFI_S3_SAVE_STATE_PROTOCOL *This,
BOOLEAN BeforeOrAfter,
BOOLEAN CreateIfNotFound,
EFI_S3_BOOT_SCRIPT_POSITION *Position ,
CHAR8 *Label
);
typedef
EFI_STATUS
( *EFI_S3_SAVE_STATE_COMPARE)(
EFI_S3_SAVE_STATE_PROTOCOL *This,
EFI_S3_BOOT_SCRIPT_POSITION Position1,
EFI_S3_BOOT_SCRIPT_POSITION Position2,
UINTN *RelativePosition
);

struct _EFI_S3_SAVE_STATE_PROTOCOL {
EFI_S3_SAVE_STATE_WRITE Write;
EFI_S3_SAVE_STATE_INSERT Insert;
EFI_S3_SAVE_STATE_LABEL Label;
EFI_S3_SAVE_STATE_COMPARE Compare;
};

extern EFI_GUID gEfiS3SaveStateProtocolGuid;
typedef EFI_S3_SAVE_STATE_PROTOCOL EFI_S3_SMM_SAVE_STATE_PROTOCOL;

extern EFI_GUID gEfiS3SmmSaveStateProtocolGuid;
typedef struct _EFI_SCSI_IO_PROTOCOL EFI_SCSI_IO_PROTOCOL;
typedef struct {
UINT64 Timeout;

void *InDataBuffer;

void *OutDataBuffer;

void *SenseData;

void *Cdb;

UINT32 InTransferLength;

UINT32 OutTransferLength;

UINT8 CdbLength;

UINT8 DataDirection;

UINT8 HostAdapterStatus;

UINT8 TargetStatus;

UINT8 SenseDataLength;
} EFI_SCSI_IO_SCSI_REQUEST_PACKET;
typedef
EFI_STATUS
( *EFI_SCSI_IO_PROTOCOL_GET_DEVICE_TYPE)(
EFI_SCSI_IO_PROTOCOL *This,
UINT8 *DeviceType
);
typedef
EFI_STATUS
( *EFI_SCSI_IO_PROTOCOL_GET_DEVICE_LOCATION)(
EFI_SCSI_IO_PROTOCOL *This,
UINT8 **Target,
UINT64 *Lun
);
typedef
EFI_STATUS
( *EFI_SCSI_IO_PROTOCOL_RESET_BUS)(
EFI_SCSI_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SCSI_IO_PROTOCOL_RESET_DEVICE)(
EFI_SCSI_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SCSI_IO_PROTOCOL_EXEC_SCSI_COMMAND)(
EFI_SCSI_IO_PROTOCOL *This,
EFI_SCSI_IO_SCSI_REQUEST_PACKET *Packet,
EFI_EVENT Event
);

struct _EFI_SCSI_IO_PROTOCOL {
EFI_SCSI_IO_PROTOCOL_GET_DEVICE_TYPE GetDeviceType;
EFI_SCSI_IO_PROTOCOL_GET_DEVICE_LOCATION GetDeviceLocation;
EFI_SCSI_IO_PROTOCOL_RESET_BUS ResetBus;
EFI_SCSI_IO_PROTOCOL_RESET_DEVICE ResetDevice;
EFI_SCSI_IO_PROTOCOL_EXEC_SCSI_COMMAND ExecuteScsiCommand;

UINT32 IoAlign;
};

extern EFI_GUID gEfiScsiIoProtocolGuid;
typedef struct _EFI_SCSI_PASS_THRU_PROTOCOL EFI_SCSI_PASS_THRU_PROTOCOL;
typedef struct {
UINT64 Timeout;

void *DataBuffer;

void *SenseData;

void *Cdb;

UINT32 TransferLength;

UINT8 CdbLength;

UINT8 DataDirection;

UINT8 HostAdapterStatus;

UINT8 TargetStatus;

UINT8 SenseDataLength;
} EFI_SCSI_PASS_THRU_SCSI_REQUEST_PACKET;

typedef struct {

CHAR16 *ControllerName;

CHAR16 *ChannelName;

UINT32 AdapterId;

UINT32 Attributes;

UINT32 IoAlign;
} EFI_SCSI_PASS_THRU_MODE;
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_PASSTHRU)(
EFI_SCSI_PASS_THRU_PROTOCOL *This,
UINT32 Target,
UINT64 Lun,
EFI_SCSI_PASS_THRU_SCSI_REQUEST_PACKET *Packet,
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_GET_NEXT_DEVICE)(
EFI_SCSI_PASS_THRU_PROTOCOL *This,
UINT32 *Target,
UINT64 *Lun
);
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_BUILD_DEVICE_PATH)(
EFI_SCSI_PASS_THRU_PROTOCOL *This,
UINT32 Target,
UINT64 Lun,
EFI_DEVICE_PATH_PROTOCOL **DevicePath
);
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_GET_TARGET_LUN)(
EFI_SCSI_PASS_THRU_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
UINT32 *Target,
UINT64 *Lun
);
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_RESET_CHANNEL)(
EFI_SCSI_PASS_THRU_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SCSI_PASS_THRU_RESET_TARGET)(
EFI_SCSI_PASS_THRU_PROTOCOL *This,
UINT32 Target,
UINT64 Lun
);
struct _EFI_SCSI_PASS_THRU_PROTOCOL {

EFI_SCSI_PASS_THRU_MODE *Mode;
EFI_SCSI_PASS_THRU_PASSTHRU PassThru;
EFI_SCSI_PASS_THRU_GET_NEXT_DEVICE GetNextDevice;
EFI_SCSI_PASS_THRU_BUILD_DEVICE_PATH BuildDevicePath;
EFI_SCSI_PASS_THRU_GET_TARGET_LUN GetTargetLun;
EFI_SCSI_PASS_THRU_RESET_CHANNEL ResetChannel;
EFI_SCSI_PASS_THRU_RESET_TARGET ResetTarget;
};

extern EFI_GUID gEfiScsiPassThruProtocolGuid;
typedef struct _EFI_EXT_SCSI_PASS_THRU_PROTOCOL EFI_EXT_SCSI_PASS_THRU_PROTOCOL;
typedef struct {

UINT32 AdapterId;

UINT32 Attributes;

UINT32 IoAlign;
} EFI_EXT_SCSI_PASS_THRU_MODE;

typedef struct {
UINT64 Timeout;

void *InDataBuffer;

void *OutDataBuffer;

void *SenseData;

void *Cdb;

UINT32 InTransferLength;

UINT32 OutTransferLength;

UINT8 CdbLength;

UINT8 DataDirection;

UINT8 HostAdapterStatus;

UINT8 TargetStatus;

UINT8 SenseDataLength;
} EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET;
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_PASSTHRU)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
UINT8 *Target,
UINT64 Lun,
EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET *Packet,
EFI_EVENT Event
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_GET_NEXT_TARGET_LUN)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
UINT8 **Target,
UINT64 *Lun
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_BUILD_DEVICE_PATH)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
UINT8 *Target,
UINT64 Lun,
EFI_DEVICE_PATH_PROTOCOL **DevicePath
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_GET_TARGET_LUN)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
EFI_DEVICE_PATH_PROTOCOL *DevicePath,
UINT8 **Target,
UINT64 *Lun
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_RESET_CHANNEL)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_RESET_TARGET_LUN)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
UINT8 *Target,
UINT64 Lun
);
typedef
EFI_STATUS
( *EFI_EXT_SCSI_PASS_THRU_GET_NEXT_TARGET)(
EFI_EXT_SCSI_PASS_THRU_PROTOCOL *This,
UINT8 **Target
);

struct _EFI_EXT_SCSI_PASS_THRU_PROTOCOL {

EFI_EXT_SCSI_PASS_THRU_MODE *Mode;
EFI_EXT_SCSI_PASS_THRU_PASSTHRU PassThru;
EFI_EXT_SCSI_PASS_THRU_GET_NEXT_TARGET_LUN GetNextTargetLun;
EFI_EXT_SCSI_PASS_THRU_BUILD_DEVICE_PATH BuildDevicePath;
EFI_EXT_SCSI_PASS_THRU_GET_TARGET_LUN GetTargetLun;
EFI_EXT_SCSI_PASS_THRU_RESET_CHANNEL ResetChannel;
EFI_EXT_SCSI_PASS_THRU_RESET_TARGET_LUN ResetTargetLun;
EFI_EXT_SCSI_PASS_THRU_GET_NEXT_TARGET GetNextTarget;
};

extern EFI_GUID gEfiExtScsiPassThruProtocolGuid;
typedef struct _EFI_SECURITY_ARCH_PROTOCOL EFI_SECURITY_ARCH_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SECURITY_FILE_AUTHENTICATION_STATE)(
EFI_SECURITY_ARCH_PROTOCOL *This,
UINT32 AuthenticationStatus,
EFI_DEVICE_PATH_PROTOCOL *File
);

struct _EFI_SECURITY_ARCH_PROTOCOL {
EFI_SECURITY_FILE_AUTHENTICATION_STATE FileAuthenticationState;
};

extern EFI_GUID gEfiSecurityArchProtocolGuid;
extern EFI_GUID gEfiSecurityPolicyProtocolGuid;
typedef struct _EFI_SERIAL_IO_PROTOCOL EFI_SERIAL_IO_PROTOCOL;

typedef EFI_SERIAL_IO_PROTOCOL SERIAL_IO_INTERFACE;

typedef enum {
DefaultParity,
NoParity,
EvenParity,
OddParity,
MarkParity,
SpaceParity
} EFI_PARITY_TYPE;

typedef enum {
DefaultStopBits,
OneStopBit,
OneFiveStopBits,
TwoStopBits
} EFI_STOP_BITS_TYPE;
typedef
EFI_STATUS
( *EFI_SERIAL_RESET)(
EFI_SERIAL_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SERIAL_SET_ATTRIBUTES)(
EFI_SERIAL_IO_PROTOCOL *This,
UINT64 BaudRate,
UINT32 ReceiveFifoDepth,
UINT32 Timeout,
EFI_PARITY_TYPE Parity,
UINT8 DataBits,
EFI_STOP_BITS_TYPE StopBits
);
typedef
EFI_STATUS
( *EFI_SERIAL_SET_CONTROL_BITS)(
EFI_SERIAL_IO_PROTOCOL *This,
UINT32 Control
);
typedef
EFI_STATUS
( *EFI_SERIAL_GET_CONTROL_BITS)(
EFI_SERIAL_IO_PROTOCOL *This,
UINT32 *Control
);
typedef
EFI_STATUS
( *EFI_SERIAL_WRITE)(
EFI_SERIAL_IO_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_SERIAL_READ)(
EFI_SERIAL_IO_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef struct {
UINT32 ControlMask;

UINT32 Timeout;
UINT64 BaudRate;
UINT32 ReceiveFifoDepth;
UINT32 DataBits;
UINT32 Parity;
UINT32 StopBits;
} EFI_SERIAL_IO_MODE;
struct _EFI_SERIAL_IO_PROTOCOL {

UINT32 Revision;
EFI_SERIAL_RESET Reset;
EFI_SERIAL_SET_ATTRIBUTES SetAttributes;
EFI_SERIAL_SET_CONTROL_BITS SetControl;
EFI_SERIAL_GET_CONTROL_BITS GetControl;
EFI_SERIAL_WRITE Write;
EFI_SERIAL_READ Read;

EFI_SERIAL_IO_MODE *Mode;
};

extern EFI_GUID gEfiSerialIoProtocolGuid;
typedef struct _EFI_SERVICE_BINDING_PROTOCOL EFI_SERVICE_BINDING_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SERVICE_BINDING_CREATE_CHILD)(
EFI_SERVICE_BINDING_PROTOCOL *This,
EFI_HANDLE *ChildHandle
);
typedef
EFI_STATUS
( *EFI_SERVICE_BINDING_DESTROY_CHILD)(
EFI_SERVICE_BINDING_PROTOCOL *This,
EFI_HANDLE ChildHandle
);
struct _EFI_SERVICE_BINDING_PROTOCOL {
EFI_SERVICE_BINDING_CREATE_CHILD CreateChild;
EFI_SERVICE_BINDING_DESTROY_CHILD DestroyChild;
};
typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

typedef struct _EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;
typedef struct _EFI_FILE_PROTOCOL *EFI_FILE_HANDLE;
typedef EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_FILE_IO_INTERFACE;
typedef EFI_FILE_PROTOCOL EFI_FILE;
typedef
EFI_STATUS
( *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME)(
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This,
EFI_FILE_PROTOCOL **Root
);
struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {

UINT64 Revision;
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME OpenVolume;
};
typedef
EFI_STATUS
( *EFI_FILE_OPEN)(
EFI_FILE_PROTOCOL *This,
EFI_FILE_PROTOCOL **NewHandle,
CHAR16 *FileName,
UINT64 OpenMode,
UINT64 Attributes
);
typedef
EFI_STATUS
( *EFI_FILE_CLOSE)(
EFI_FILE_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_FILE_DELETE)(
EFI_FILE_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_FILE_READ)(
EFI_FILE_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_FILE_WRITE)(
EFI_FILE_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_FILE_SET_POSITION)(
EFI_FILE_PROTOCOL *This,
UINT64 Position
);
typedef
EFI_STATUS
( *EFI_FILE_GET_POSITION)(
EFI_FILE_PROTOCOL *This,
UINT64 *Position
);
typedef
EFI_STATUS
( *EFI_FILE_GET_INFO)(
EFI_FILE_PROTOCOL *This,
EFI_GUID *InformationType,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_FILE_SET_INFO)(
EFI_FILE_PROTOCOL *This,
EFI_GUID *InformationType,
UINTN BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_FILE_FLUSH)(
EFI_FILE_PROTOCOL *This
);
struct _EFI_FILE_PROTOCOL {

UINT64 Revision;
EFI_FILE_OPEN Open;
EFI_FILE_CLOSE Close;
EFI_FILE_DELETE Delete;
EFI_FILE_READ Read;
EFI_FILE_WRITE Write;
EFI_FILE_GET_POSITION GetPosition;
EFI_FILE_SET_POSITION SetPosition;
EFI_FILE_GET_INFO GetInfo;
EFI_FILE_SET_INFO SetInfo;
EFI_FILE_FLUSH Flush;
};

extern EFI_GUID gEfiSimpleFileSystemProtocolGuid;

typedef struct _EFI_SIMPLE_POINTER_PROTOCOL EFI_SIMPLE_POINTER_PROTOCOL;

typedef struct {

INT32 RelativeMovementX;

INT32 RelativeMovementY;

INT32 RelativeMovementZ;

BOOLEAN LeftButton;

BOOLEAN RightButton;
} EFI_SIMPLE_POINTER_STATE;

typedef struct {

UINT64 ResolutionX;

UINT64 ResolutionY;

UINT64 ResolutionZ;

BOOLEAN LeftButton;

BOOLEAN RightButton;
} EFI_SIMPLE_POINTER_MODE;
typedef
EFI_STATUS
( *EFI_SIMPLE_POINTER_RESET)(
EFI_SIMPLE_POINTER_PROTOCOL *This,
BOOLEAN ExtendedVerification
);
typedef
EFI_STATUS
( *EFI_SIMPLE_POINTER_GET_STATE)(
EFI_SIMPLE_POINTER_PROTOCOL *This,
EFI_SIMPLE_POINTER_STATE *State
);
struct _EFI_SIMPLE_POINTER_PROTOCOL {
EFI_SIMPLE_POINTER_RESET Reset;
EFI_SIMPLE_POINTER_GET_STATE GetState;

EFI_EVENT WaitForInput;

EFI_SIMPLE_POINTER_MODE *Mode;
};

extern EFI_GUID gEfiSimplePointerProtocolGuid;

typedef UINT8 EFI_SMBIOS_STRING;

typedef UINT8 EFI_SMBIOS_TYPE;
typedef UINT16 EFI_SMBIOS_HANDLE;

typedef struct {
EFI_SMBIOS_TYPE Type;
UINT8 Length;
EFI_SMBIOS_HANDLE Handle;
} EFI_SMBIOS_TABLE_HEADER;

typedef struct _EFI_SMBIOS_PROTOCOL EFI_SMBIOS_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMBIOS_ADD)(
EFI_SMBIOS_PROTOCOL *This,
EFI_HANDLE ProducerHandle ,
EFI_SMBIOS_HANDLE *SmbiosHandle,
EFI_SMBIOS_TABLE_HEADER *Record
);
typedef
EFI_STATUS
( *EFI_SMBIOS_UPDATE_STRING)(
EFI_SMBIOS_PROTOCOL *This,
EFI_SMBIOS_HANDLE *SmbiosHandle,
UINTN *StringNumber,
CHAR8 *String
);
typedef
EFI_STATUS
( *EFI_SMBIOS_REMOVE)(
EFI_SMBIOS_PROTOCOL *This,
EFI_SMBIOS_HANDLE SmbiosHandle
);
typedef
EFI_STATUS
( *EFI_SMBIOS_GET_NEXT)(
EFI_SMBIOS_PROTOCOL *This,
EFI_SMBIOS_HANDLE *SmbiosHandle,
EFI_SMBIOS_TYPE *Type ,
EFI_SMBIOS_TABLE_HEADER **Record,
EFI_HANDLE *ProducerHandle
);

struct _EFI_SMBIOS_PROTOCOL {
EFI_SMBIOS_ADD Add;
EFI_SMBIOS_UPDATE_STRING UpdateString;
EFI_SMBIOS_REMOVE Remove;
EFI_SMBIOS_GET_NEXT GetNext;
UINT8 MajorVersion;
UINT8 MinorVersion;
};

extern EFI_GUID gEfiSmbiosProtocolGuid;
typedef struct {
UINT32 VendorSpecificId;
UINT16 SubsystemDeviceId;
UINT16 SubsystemVendorId;
UINT16 Interface;
UINT16 DeviceId;
UINT16 VendorId;
UINT8 VendorRevision;
UINT8 DeviceCapabilities;
} EFI_SMBUS_UDID;

typedef struct {

UINTN SmbusDeviceAddress : 7;
} EFI_SMBUS_DEVICE_ADDRESS;

typedef struct {

EFI_SMBUS_DEVICE_ADDRESS SmbusDeviceAddress;

EFI_SMBUS_UDID SmbusDeviceUdid;
} EFI_SMBUS_DEVICE_MAP;

typedef enum _EFI_SMBUS_OPERATION {
EfiSmbusQuickRead,
EfiSmbusQuickWrite,
EfiSmbusReceiveByte,
EfiSmbusSendByte,
EfiSmbusReadByte,
EfiSmbusWriteByte,
EfiSmbusReadWord,
EfiSmbusWriteWord,
EfiSmbusReadBlock,
EfiSmbusWriteBlock,
EfiSmbusProcessCall,
EfiSmbusBWBRProcessCall
} EFI_SMBUS_OPERATION;

typedef UINTN EFI_SMBUS_DEVICE_COMMAND;

typedef struct _EFI_SMBUS_HC_PROTOCOL EFI_SMBUS_HC_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMBUS_HC_EXECUTE_OPERATION)(
EFI_SMBUS_HC_PROTOCOL *This,
EFI_SMBUS_DEVICE_ADDRESS SlaveAddress,
EFI_SMBUS_DEVICE_COMMAND Command,
EFI_SMBUS_OPERATION Operation,
BOOLEAN PecCheck,
UINTN *Length,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_SMBUS_HC_PROTOCOL_ARP_DEVICE)(
EFI_SMBUS_HC_PROTOCOL *This,
BOOLEAN ArpAll,
EFI_SMBUS_UDID *SmbusUdid,
EFI_SMBUS_DEVICE_ADDRESS *SlaveAddress
);
typedef
EFI_STATUS
( *EFI_SMBUS_HC_PROTOCOL_GET_ARP_MAP)(
EFI_SMBUS_HC_PROTOCOL *This,
UINTN *Length,
EFI_SMBUS_DEVICE_MAP **SmbusDeviceMap
);
typedef
EFI_STATUS
( *EFI_SMBUS_NOTIFY_FUNCTION)(
EFI_SMBUS_DEVICE_ADDRESS SlaveAddress,
UINTN Data
);
typedef
EFI_STATUS
( *EFI_SMBUS_HC_PROTOCOL_NOTIFY)(
EFI_SMBUS_HC_PROTOCOL *This,
EFI_SMBUS_DEVICE_ADDRESS SlaveAddress,
UINTN Data,
EFI_SMBUS_NOTIFY_FUNCTION NotifyFunction
);

struct _EFI_SMBUS_HC_PROTOCOL {
EFI_SMBUS_HC_EXECUTE_OPERATION Execute;
EFI_SMBUS_HC_PROTOCOL_ARP_DEVICE ArpDevice;
EFI_SMBUS_HC_PROTOCOL_GET_ARP_MAP GetArpMap;
EFI_SMBUS_HC_PROTOCOL_NOTIFY Notify;
};

extern EFI_GUID gEfiSmbusHcProtocolGuid;
typedef struct _EFI_SMM_ACCESS2_PROTOCOL EFI_SMM_ACCESS2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_OPEN2)(
EFI_SMM_ACCESS2_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SMM_CLOSE2)(
EFI_SMM_ACCESS2_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SMM_LOCK2)(
EFI_SMM_ACCESS2_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_SMM_CAPABILITIES2)(
EFI_SMM_ACCESS2_PROTOCOL *This,
UINTN *SmramMapSize,
EFI_SMRAM_DESCRIPTOR *SmramMap
);

struct _EFI_SMM_ACCESS2_PROTOCOL {
EFI_SMM_OPEN2 Open;
EFI_SMM_CLOSE2 Close;
EFI_SMM_LOCK2 Lock;
EFI_SMM_CAPABILITIES2 GetCapabilities;

BOOLEAN LockState;

BOOLEAN OpenState;
};

extern EFI_GUID gEfiSmmAccess2ProtocolGuid;
typedef struct _EFI_SMM_CPU_IO2_PROTOCOL EFI_SMM_CPU_IO2_PROTOCOL;

typedef enum {
SMM_IO_UINT8 = 0,
SMM_IO_UINT16 = 1,
SMM_IO_UINT32 = 2,
SMM_IO_UINT64 = 3
} EFI_SMM_IO_WIDTH;
typedef
EFI_STATUS
( *EFI_SMM_CPU_IO2)(
EFI_SMM_CPU_IO2_PROTOCOL *This,
EFI_SMM_IO_WIDTH Width,
UINT64 Address,
UINTN Count,
void *Buffer
);

typedef struct {

EFI_SMM_CPU_IO2 Read;

EFI_SMM_CPU_IO2 Write;
} EFI_SMM_IO_ACCESS2;

struct _EFI_SMM_CPU_IO2_PROTOCOL {

EFI_SMM_IO_ACCESS2 Mem;

EFI_SMM_IO_ACCESS2 Io;
};

extern EFI_GUID gEfiSmmCpuIo2ProtocolGuid;

typedef struct _EFI_SMM_SYSTEM_TABLE2 EFI_SMM_SYSTEM_TABLE2;
typedef
EFI_STATUS
( *EFI_SMM_INSTALL_CONFIGURATION_TABLE2)(
EFI_SMM_SYSTEM_TABLE2 *SystemTable,
EFI_GUID *Guid,
void *Table,
UINTN TableSize
);
typedef
EFI_STATUS
( *EFI_SMM_STARTUP_THIS_AP)(
EFI_AP_PROCEDURE Procedure,
UINTN CpuNumber,
void *ProcArguments
);
typedef
EFI_STATUS
( *EFI_SMM_NOTIFY_FN)(
EFI_GUID *Protocol,
void *Interface,
EFI_HANDLE Handle
);
typedef
EFI_STATUS
( *EFI_SMM_REGISTER_PROTOCOL_NOTIFY)(
EFI_GUID *Protocol,
EFI_SMM_NOTIFY_FN Function,
void **Registration
);
typedef
EFI_STATUS
( *EFI_SMM_INTERRUPT_MANAGE)(
EFI_GUID *HandlerType,
void *Context ,
void *CommBuffer ,
UINTN *CommBufferSize
);
typedef
EFI_STATUS
( *EFI_SMM_HANDLER_ENTRY_POINT2)(
EFI_HANDLE DispatchHandle,
void *Context ,
void *CommBuffer ,
UINTN *CommBufferSize
);
typedef
EFI_STATUS
( *EFI_SMM_INTERRUPT_REGISTER)(
EFI_SMM_HANDLER_ENTRY_POINT2 Handler,
EFI_GUID *HandlerType ,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_INTERRUPT_UNREGISTER)(
EFI_HANDLE DispatchHandle
);

typedef struct _EFI_SMM_ENTRY_CONTEXT {
EFI_SMM_STARTUP_THIS_AP SmmStartupThisAp;

UINTN CurrentlyExecutingCpu;

UINTN NumberOfCpus;

UINTN *CpuSaveStateSize;

void **CpuSaveState;
} EFI_SMM_ENTRY_CONTEXT;

typedef
void
( *EFI_SMM_ENTRY_POINT)(
EFI_SMM_ENTRY_CONTEXT *SmmEntryContext
);
struct _EFI_SMM_SYSTEM_TABLE2 {

EFI_TABLE_HEADER Hdr;

CHAR16 *SmmFirmwareVendor;

UINT32 SmmFirmwareRevision;

EFI_SMM_INSTALL_CONFIGURATION_TABLE2 SmmInstallConfigurationTable;

EFI_SMM_CPU_IO2_PROTOCOL SmmIo;

EFI_ALLOCATE_POOL SmmAllocatePool;
EFI_FREE_POOL SmmFreePool;
EFI_ALLOCATE_PAGES SmmAllocatePages;
EFI_FREE_PAGES SmmFreePages;

EFI_SMM_STARTUP_THIS_AP SmmStartupThisAp;
UINTN CurrentlyExecutingCpu;

UINTN NumberOfCpus;

UINTN *CpuSaveStateSize;

void **CpuSaveState;
UINTN NumberOfTableEntries;

EFI_CONFIGURATION_TABLE *SmmConfigurationTable;

EFI_INSTALL_PROTOCOL_INTERFACE SmmInstallProtocolInterface;
EFI_UNINSTALL_PROTOCOL_INTERFACE SmmUninstallProtocolInterface;
EFI_HANDLE_PROTOCOL SmmHandleProtocol;
EFI_SMM_REGISTER_PROTOCOL_NOTIFY SmmRegisterProtocolNotify;
EFI_LOCATE_HANDLE SmmLocateHandle;
EFI_LOCATE_PROTOCOL SmmLocateProtocol;

EFI_SMM_INTERRUPT_MANAGE SmiManage;
EFI_SMM_INTERRUPT_REGISTER SmiHandlerRegister;
EFI_SMM_INTERRUPT_UNREGISTER SmiHandlerUnRegister;
};

typedef struct _EFI_SMM_SYSTEM_TABLE2_FIXUP {

EFI_TABLE_HEADER Hdr;

CHAR16 *SmmFirmwareVendor;
UINT32 FILLER1;
UINT32 SmmFirmwareRevision;
UINT32 FILLER2;
EFI_SMM_INSTALL_CONFIGURATION_TABLE2 SmmInstallConfigurationTable;

EFI_SMM_CPU_IO2_PROTOCOL SmmIo;

EFI_ALLOCATE_POOL SmmAllocatePool;
EFI_FREE_POOL SmmFreePool;
EFI_ALLOCATE_PAGES SmmAllocatePages;
EFI_FREE_PAGES SmmFreePages;

EFI_SMM_STARTUP_THIS_AP SmmStartupThisAp;
UINTN CurrentlyExecutingCpu;

UINTN NumberOfCpus;

UINTN *CpuSaveStateSize;

void **CpuSaveState;
UINTN NumberOfTableEntries;
UINT32 FILLER3;

EFI_CONFIGURATION_TABLE *SmmConfigurationTable;

EFI_INSTALL_PROTOCOL_INTERFACE SmmInstallProtocolInterface;
EFI_UNINSTALL_PROTOCOL_INTERFACE SmmUninstallProtocolInterface;
EFI_HANDLE_PROTOCOL SmmHandleProtocol;
EFI_SMM_REGISTER_PROTOCOL_NOTIFY SmmRegisterProtocolNotify;
EFI_LOCATE_HANDLE SmmLocateHandle;
EFI_LOCATE_PROTOCOL SmmLocateProtocol;

EFI_SMM_INTERRUPT_MANAGE SmiManage;
EFI_SMM_INTERRUPT_REGISTER SmiHandlerRegister;
EFI_SMM_INTERRUPT_UNREGISTER SmiHandlerUnRegister;
} EFI_SMM_SYSTEM_TABLE2_FIXUP;

typedef struct _EFI_SMM_BASE2_PROTOCOL EFI_SMM_BASE2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_INSIDE_OUT2)(
EFI_SMM_BASE2_PROTOCOL *This,
BOOLEAN *InSmram
)
;
typedef
EFI_STATUS
( *EFI_SMM_GET_SMST_LOCATION2)(
EFI_SMM_BASE2_PROTOCOL *This,
EFI_SMM_SYSTEM_TABLE2 **Smst
)
;

struct _EFI_SMM_BASE2_PROTOCOL {
EFI_SMM_INSIDE_OUT2 InSmm;
EFI_SMM_GET_SMST_LOCATION2 GetSmstLocation;
};

extern EFI_GUID gEfiSmmBase2ProtocolGuid;

typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_COMMON_HEADER;

#pragma pack(1)

typedef struct {
UINT32 Signature;
UINT32 Length;
UINT8 Revision;
UINT8 Checksum;
UINT8 OemId[6];
UINT64 OemTableId;
UINT32 OemRevision;
UINT32 CreatorId;
UINT32 CreatorRevision;
} EFI_ACPI_DESCRIPTION_HEADER;
#pragma pack()
#pragma pack(1)

typedef struct {
UINT8 Desc;
UINT16 Len;
UINT8 ResType;
UINT8 GenFlag;
UINT8 SpecificFlag;
UINT64 AddrSpaceGranularity;
UINT64 AddrRangeMin;
UINT64 AddrRangeMax;
UINT64 AddrTranslationOffset;
UINT64 AddrLen;
} EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR;

typedef union {
UINT8 Byte;
struct {
UINT8 Length : 3;
UINT8 Name : 4;
UINT8 Type : 1;
} Bits;
} ACPI_SMALL_RESOURCE_HEADER;

typedef struct {
union {
UINT8 Byte;
struct {
UINT8 Name : 7;
UINT8 Type : 1;
}Bits;
} Header;
UINT16 Length;
} ACPI_LARGE_RESOURCE_HEADER;

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT16 Mask;
} EFI_ACPI_IRQ_NOFLAG_DESCRIPTOR;

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT16 Mask;
UINT8 Information;
} EFI_ACPI_IRQ_DESCRIPTOR;

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT8 ChannelMask;
UINT8 Information;
} EFI_ACPI_DMA_DESCRIPTOR;

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT8 Information;
UINT16 BaseAddressMin;
UINT16 BaseAddressMax;
UINT8 Alignment;
UINT8 Length;
} EFI_ACPI_IO_PORT_DESCRIPTOR;

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT16 BaseAddress;
UINT8 Length;
} EFI_ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 Information;
UINT16 BaseAddressMin;
UINT16 BaseAddressMax;
UINT16 Alignment;
UINT16 Length;
} EFI_ACPI_24_BIT_MEMORY_RANGE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 Information;
UINT32 BaseAddressMin;
UINT32 BaseAddressMax;
UINT32 Alignment;
UINT32 Length;
} EFI_ACPI_32_BIT_MEMORY_RANGE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 Information;
UINT32 BaseAddress;
UINT32 Length;
} EFI_ACPI_32_BIT_FIXED_MEMORY_RANGE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 ResType;
UINT8 GenFlag;
UINT8 SpecificFlag;
UINT64 AddrSpaceGranularity;
UINT64 AddrRangeMin;
UINT64 AddrRangeMax;
UINT64 AddrTranslationOffset;
UINT64 AddrLen;
} EFI_ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 ResType;
UINT8 GenFlag;
UINT8 SpecificFlag;
UINT32 AddrSpaceGranularity;
UINT32 AddrRangeMin;
UINT32 AddrRangeMax;
UINT32 AddrTranslationOffset;
UINT32 AddrLen;
} EFI_ACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 ResType;
UINT8 GenFlag;
UINT8 SpecificFlag;
UINT16 AddrSpaceGranularity;
UINT16 AddrRangeMin;
UINT16 AddrRangeMax;
UINT16 AddrTranslationOffset;
UINT16 AddrLen;
} EFI_ACPI_WORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 InterruptVectorFlags;
UINT8 InterruptTableLength;
UINT32 InterruptNumber[1];
} EFI_ACPI_EXTENDED_INTERRUPT_DESCRIPTOR;

#pragma pack()

typedef struct {
UINT8 Desc;
UINT8 Checksum;
} EFI_ACPI_END_TAG_DESCRIPTOR;
#pragma pack(1)

typedef struct {
UINT64 Signature;
UINT8 Checksum;
UINT8 OemId[6];
UINT8 Reserved;
UINT32 RsdtAddress;
} EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 FirmwareCtrl;
UINT32 Dsdt;
UINT8 IntModel;
UINT8 Reserved1;
UINT16 SciInt;
UINT32 SmiCmd;
UINT8 AcpiEnable;
UINT8 AcpiDisable;
UINT8 S4BiosReq;
UINT8 Reserved2;
UINT32 Pm1aEvtBlk;
UINT32 Pm1bEvtBlk;
UINT32 Pm1aCntBlk;
UINT32 Pm1bCntBlk;
UINT32 Pm2CntBlk;
UINT32 PmTmrBlk;
UINT32 Gpe0Blk;
UINT32 Gpe1Blk;
UINT8 Pm1EvtLen;
UINT8 Pm1CntLen;
UINT8 Pm2CntLen;
UINT8 PmTmLen;
UINT8 Gpe0BlkLen;
UINT8 Gpe1BlkLen;
UINT8 Gpe1Base;
UINT8 Reserved3;
UINT16 PLvl2Lat;
UINT16 PLvl3Lat;
UINT16 FlushSize;
UINT16 FlushStride;
UINT8 DutyOffset;
UINT8 DutyWidth;
UINT8 DayAlrm;
UINT8 MonAlrm;
UINT8 Century;
UINT8 Reserved4;
UINT8 Reserved5;
UINT8 Reserved6;
UINT32 Flags;
} EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT32 HardwareSignature;
UINT32 FirmwareWakingVector;
UINT32 GlobalLock;
UINT32 Flags;
UINT8 Reserved[40];
} EFI_ACPI_1_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 LocalApicAddress;
UINT32 Flags;
} EFI_ACPI_1_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 ApicId;
UINT32 Flags;
} EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 IoApicAddress;
UINT32 SystemVectorBase;
} EFI_ACPI_1_0_IO_APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Bus;
UINT8 Source;
UINT32 GlobalSystemInterruptVector;
UINT16 Flags;
} EFI_ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 GlobalSystemInterruptVector;
} EFI_ACPI_1_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT16 Flags;
UINT8 LocalApicInti;
} EFI_ACPI_1_0_LOCAL_APIC_NMI_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 WarningEnergyLevel;
UINT32 LowEnergyLevel;
UINT32 CriticalEnergyLevel;
} EFI_ACPI_1_0_SMART_BATTERY_DESCRIPTION_TABLE;
#pragma pack()
#pragma pack(1)

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 AddressSpaceId;
UINT8 RegisterBitWidth;
UINT8 RegisterBitOffset;
UINT8 AddressSize;
UINT64 RegisterAddress;
} EFI_ACPI_GENERIC_REGISTER_DESCRIPTOR;

#pragma pack()

#pragma pack(1)

typedef struct {
UINT8 AddressSpaceId;
UINT8 RegisterBitWidth;
UINT8 RegisterBitOffset;
UINT8 Reserved;
UINT64 Address;
} EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE;
typedef struct {
UINT64 Signature;
UINT8 Checksum;
UINT8 OemId[6];
UINT8 Revision;
UINT32 RsdtAddress;
UINT32 Length;
UINT64 XsdtAddress;
UINT8 ExtendedChecksum;
UINT8 Reserved[3];
} EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER;
typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_2_0_COMMON_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 FirmwareCtrl;
UINT32 Dsdt;
UINT8 Reserved0;
UINT8 PreferredPmProfile;
UINT16 SciInt;
UINT32 SmiCmd;
UINT8 AcpiEnable;
UINT8 AcpiDisable;
UINT8 S4BiosReq;
UINT8 PstateCnt;
UINT32 Pm1aEvtBlk;
UINT32 Pm1bEvtBlk;
UINT32 Pm1aCntBlk;
UINT32 Pm1bCntBlk;
UINT32 Pm2CntBlk;
UINT32 PmTmrBlk;
UINT32 Gpe0Blk;
UINT32 Gpe1Blk;
UINT8 Pm1EvtLen;
UINT8 Pm1CntLen;
UINT8 Pm2CntLen;
UINT8 PmTmrLen;
UINT8 Gpe0BlkLen;
UINT8 Gpe1BlkLen;
UINT8 Gpe1Base;
UINT8 CstCnt;
UINT16 PLvl2Lat;
UINT16 PLvl3Lat;
UINT16 FlushSize;
UINT16 FlushStride;
UINT8 DutyOffset;
UINT8 DutyWidth;
UINT8 DayAlrm;
UINT8 MonAlrm;
UINT8 Century;
UINT16 IaPcBootArch;
UINT8 Reserved1;
UINT32 Flags;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE ResetReg;
UINT8 ResetValue;
UINT8 Reserved2[3];
UINT64 XFirmwareCtrl;
UINT64 XDsdt;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPm1aEvtBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPm1bEvtBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPm1aCntBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPm1bCntBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPm2CntBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XPmTmrBlk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XGpe0Blk;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE XGpe1Blk;
} EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT32 HardwareSignature;
UINT32 FirmwareWakingVector;
UINT32 GlobalLock;
UINT32 Flags;
UINT64 XFirmwareWakingVector;
UINT8 Version;
UINT8 Reserved[31];
} EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 LocalApicAddress;
UINT32 Flags;
} EFI_ACPI_2_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 ApicId;
UINT32 Flags;
} EFI_ACPI_2_0_PROCESSOR_LOCAL_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 IoApicAddress;
UINT32 GlobalSystemInterruptBase;
} EFI_ACPI_2_0_IO_APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Bus;
UINT8 Source;
UINT32 GlobalSystemInterrupt;
UINT16 Flags;
} EFI_ACPI_2_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 GlobalSystemInterrupt;
} EFI_ACPI_2_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT16 Flags;
UINT8 LocalApicLint;
} EFI_ACPI_2_0_LOCAL_APIC_NMI_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved;
UINT64 LocalApicAddress;
} EFI_ACPI_2_0_LOCAL_APIC_ADDRESS_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 GlobalSystemInterruptBase;
UINT64 IoSapicAddress;
} EFI_ACPI_2_0_IO_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 LocalSapicId;
UINT8 LocalSapicEid;
UINT8 Reserved[3];
UINT32 Flags;
} EFI_ACPI_2_0_PROCESSOR_LOCAL_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 Reserved;
} EFI_ACPI_2_0_PLATFORM_INTERRUPT_SOURCES_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 WarningEnergyLevel;
UINT32 LowEnergyLevel;
UINT32 CriticalEnergyLevel;
} EFI_ACPI_2_0_SMART_BATTERY_DESCRIPTION_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE EcControl;
EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE EcData;
UINT32 Uid;
UINT8 GpeBit;
} EFI_ACPI_2_0_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE;
#pragma pack()
#pragma pack(1)

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 ResType;
UINT8 GenFlag;
UINT8 SpecificFlag;
UINT8 RevisionId;
UINT8 Reserved;
UINT64 AddrSpaceGranularity;
UINT64 AddrRangeMin;
UINT64 AddrRangeMax;
UINT64 AddrTranslationOffset;
UINT64 AddrLen;
UINT64 TypeSpecificAttribute;
} EFI_ACPI_EXTENDED_ADDRESS_SPACE_DESCRIPTOR;

#pragma pack()
#pragma pack(1)

typedef struct {
UINT8 AddressSpaceId;
UINT8 RegisterBitWidth;
UINT8 RegisterBitOffset;
UINT8 AccessSize;
UINT64 Address;
} EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE;
typedef struct {
UINT64 Signature;
UINT8 Checksum;
UINT8 OemId[6];
UINT8 Revision;
UINT32 RsdtAddress;
UINT32 Length;
UINT64 XsdtAddress;
UINT8 ExtendedChecksum;
UINT8 Reserved[3];
} EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER;
typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_3_0_COMMON_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 FirmwareCtrl;
UINT32 Dsdt;
UINT8 Reserved0;
UINT8 PreferredPmProfile;
UINT16 SciInt;
UINT32 SmiCmd;
UINT8 AcpiEnable;
UINT8 AcpiDisable;
UINT8 S4BiosReq;
UINT8 PstateCnt;
UINT32 Pm1aEvtBlk;
UINT32 Pm1bEvtBlk;
UINT32 Pm1aCntBlk;
UINT32 Pm1bCntBlk;
UINT32 Pm2CntBlk;
UINT32 PmTmrBlk;
UINT32 Gpe0Blk;
UINT32 Gpe1Blk;
UINT8 Pm1EvtLen;
UINT8 Pm1CntLen;
UINT8 Pm2CntLen;
UINT8 PmTmrLen;
UINT8 Gpe0BlkLen;
UINT8 Gpe1BlkLen;
UINT8 Gpe1Base;
UINT8 CstCnt;
UINT16 PLvl2Lat;
UINT16 PLvl3Lat;
UINT16 FlushSize;
UINT16 FlushStride;
UINT8 DutyOffset;
UINT8 DutyWidth;
UINT8 DayAlrm;
UINT8 MonAlrm;
UINT8 Century;
UINT16 IaPcBootArch;
UINT8 Reserved1;
UINT32 Flags;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE ResetReg;
UINT8 ResetValue;
UINT8 Reserved2[3];
UINT64 XFirmwareCtrl;
UINT64 XDsdt;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPm1aEvtBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPm1bEvtBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPm1aCntBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPm1bCntBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPm2CntBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XPmTmrBlk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XGpe0Blk;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE XGpe1Blk;
} EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT32 HardwareSignature;
UINT32 FirmwareWakingVector;
UINT32 GlobalLock;
UINT32 Flags;
UINT64 XFirmwareWakingVector;
UINT8 Version;
UINT8 Reserved[31];
} EFI_ACPI_3_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 LocalApicAddress;
UINT32 Flags;
} EFI_ACPI_3_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 ApicId;
UINT32 Flags;
} EFI_ACPI_3_0_PROCESSOR_LOCAL_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 IoApicAddress;
UINT32 GlobalSystemInterruptBase;
} EFI_ACPI_3_0_IO_APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Bus;
UINT8 Source;
UINT32 GlobalSystemInterrupt;
UINT16 Flags;
} EFI_ACPI_3_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
UINT8 CpeiProcessorOverride;
UINT8 Reserved[31];
} EFI_ACPI_3_0_PLATFORM_INTERRUPT_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 GlobalSystemInterrupt;
} EFI_ACPI_3_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT16 Flags;
UINT8 LocalApicLint;
} EFI_ACPI_3_0_LOCAL_APIC_NMI_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved;
UINT64 LocalApicAddress;
} EFI_ACPI_3_0_LOCAL_APIC_ADDRESS_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 GlobalSystemInterruptBase;
UINT64 IoSapicAddress;
} EFI_ACPI_3_0_IO_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 LocalSapicId;
UINT8 LocalSapicEid;
UINT8 Reserved[3];
UINT32 Flags;
UINT32 ACPIProcessorUIDValue;
} EFI_ACPI_3_0_PROCESSOR_LOCAL_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
} EFI_ACPI_3_0_PLATFORM_INTERRUPT_SOURCES_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 WarningEnergyLevel;
UINT32 LowEnergyLevel;
UINT32 CriticalEnergyLevel;
} EFI_ACPI_3_0_SMART_BATTERY_DESCRIPTION_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE EcControl;
EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE EcData;
UINT32 Uid;
UINT8 GpeBit;
} EFI_ACPI_3_0_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 Reserved1;
UINT64 Reserved2;
} EFI_ACPI_3_0_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 ProximityDomain7To0;
UINT8 ApicId;
UINT32 Flags;
UINT8 LocalSapicEid;
UINT8 ProximityDomain31To8[3];
UINT8 Reserved[4];
} EFI_ACPI_3_0_PROCESSOR_LOCAL_APIC_SAPIC_AFFINITY_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT32 ProximityDomain;
UINT16 Reserved1;
UINT32 AddressBaseLow;
UINT32 AddressBaseHigh;
UINT32 LengthLow;
UINT32 LengthHigh;
UINT32 Reserved2;
UINT32 Flags;
UINT64 Reserved3;
} EFI_ACPI_3_0_MEMORY_AFFINITY_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT64 NumberOfSystemLocalities;
} EFI_ACPI_3_0_SYSTEM_LOCALITY_DISTANCE_INFORMATION_TABLE_HEADER;
#pragma pack()

#pragma pack(1)

typedef struct {
UINT8 AddressSpaceId;
UINT8 RegisterBitWidth;
UINT8 RegisterBitOffset;
UINT8 AccessSize;
UINT64 Address;
} EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE;
typedef struct {
UINT64 Signature;
UINT8 Checksum;
UINT8 OemId[6];
UINT8 Revision;
UINT32 RsdtAddress;
UINT32 Length;
UINT64 XsdtAddress;
UINT8 ExtendedChecksum;
UINT8 Reserved[3];
} EFI_ACPI_4_0_ROOT_SYSTEM_DESCRIPTION_POINTER;
typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_4_0_COMMON_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 FirmwareCtrl;
UINT32 Dsdt;
UINT8 Reserved0;
UINT8 PreferredPmProfile;
UINT16 SciInt;
UINT32 SmiCmd;
UINT8 AcpiEnable;
UINT8 AcpiDisable;
UINT8 S4BiosReq;
UINT8 PstateCnt;
UINT32 Pm1aEvtBlk;
UINT32 Pm1bEvtBlk;
UINT32 Pm1aCntBlk;
UINT32 Pm1bCntBlk;
UINT32 Pm2CntBlk;
UINT32 PmTmrBlk;
UINT32 Gpe0Blk;
UINT32 Gpe1Blk;
UINT8 Pm1EvtLen;
UINT8 Pm1CntLen;
UINT8 Pm2CntLen;
UINT8 PmTmrLen;
UINT8 Gpe0BlkLen;
UINT8 Gpe1BlkLen;
UINT8 Gpe1Base;
UINT8 CstCnt;
UINT16 PLvl2Lat;
UINT16 PLvl3Lat;
UINT16 FlushSize;
UINT16 FlushStride;
UINT8 DutyOffset;
UINT8 DutyWidth;
UINT8 DayAlrm;
UINT8 MonAlrm;
UINT8 Century;
UINT16 IaPcBootArch;
UINT8 Reserved1;
UINT32 Flags;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE ResetReg;
UINT8 ResetValue;
UINT8 Reserved2[3];
UINT64 XFirmwareCtrl;
UINT64 XDsdt;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPm1aEvtBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPm1bEvtBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPm1aCntBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPm1bCntBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPm2CntBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XPmTmrBlk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XGpe0Blk;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE XGpe1Blk;
} EFI_ACPI_4_0_FIXED_ACPI_DESCRIPTION_TABLE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT32 HardwareSignature;
UINT32 FirmwareWakingVector;
UINT32 GlobalLock;
UINT32 Flags;
UINT64 XFirmwareWakingVector;
UINT8 Version;
UINT8 Reserved0[3];
UINT32 OspmFlags;
UINT8 Reserved1[24];
} EFI_ACPI_4_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 LocalApicAddress;
UINT32 Flags;
} EFI_ACPI_4_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 ApicId;
UINT32 Flags;
} EFI_ACPI_4_0_PROCESSOR_LOCAL_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 IoApicAddress;
UINT32 GlobalSystemInterruptBase;
} EFI_ACPI_4_0_IO_APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Bus;
UINT8 Source;
UINT32 GlobalSystemInterrupt;
UINT16 Flags;
} EFI_ACPI_4_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
UINT8 CpeiProcessorOverride;
UINT8 Reserved[31];
} EFI_ACPI_4_0_PLATFORM_INTERRUPT_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 GlobalSystemInterrupt;
} EFI_ACPI_4_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT16 Flags;
UINT8 LocalApicLint;
} EFI_ACPI_4_0_LOCAL_APIC_NMI_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved;
UINT64 LocalApicAddress;
} EFI_ACPI_4_0_LOCAL_APIC_ADDRESS_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 GlobalSystemInterruptBase;
UINT64 IoSapicAddress;
} EFI_ACPI_4_0_IO_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 LocalSapicId;
UINT8 LocalSapicEid;
UINT8 Reserved[3];
UINT32 Flags;
UINT32 ACPIProcessorUIDValue;
} EFI_ACPI_4_0_PROCESSOR_LOCAL_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
} EFI_ACPI_4_0_PLATFORM_INTERRUPT_SOURCES_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Reserved[2];
UINT32 X2ApicId;
UINT32 Flags;
UINT32 AcpiProcessorUid;
} EFI_ACPI_4_0_PROCESSOR_LOCAL_X2APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 AcpiProcessorUid;
UINT8 LocalX2ApicLint;
UINT8 Reserved[3];
} EFI_ACPI_4_0_LOCAL_X2APIC_NMI_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 WarningEnergyLevel;
UINT32 LowEnergyLevel;
UINT32 CriticalEnergyLevel;
} EFI_ACPI_4_0_SMART_BATTERY_DESCRIPTION_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE EcControl;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE EcData;
UINT32 Uid;
UINT8 GpeBit;
} EFI_ACPI_4_0_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 Reserved1;
UINT64 Reserved2;
} EFI_ACPI_4_0_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 ProximityDomain7To0;
UINT8 ApicId;
UINT32 Flags;
UINT8 LocalSapicEid;
UINT8 ProximityDomain31To8[3];
UINT32 ClockDomain;
} EFI_ACPI_4_0_PROCESSOR_LOCAL_APIC_SAPIC_AFFINITY_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT32 ProximityDomain;
UINT16 Reserved1;
UINT32 AddressBaseLow;
UINT32 AddressBaseHigh;
UINT32 LengthLow;
UINT32 LengthHigh;
UINT32 Reserved2;
UINT32 Flags;
UINT64 Reserved3;
} EFI_ACPI_4_0_MEMORY_AFFINITY_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Reserved1[2];
UINT32 ProximityDomain;
UINT32 X2ApicId;
UINT32 Flags;
UINT32 ClockDomain;
UINT8 Reserved2[4];
} EFI_ACPI_4_0_PROCESSOR_LOCAL_X2APIC_AFFINITY_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT64 NumberOfSystemLocalities;
} EFI_ACPI_4_0_SYSTEM_LOCALITY_DISTANCE_INFORMATION_TABLE_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT8 Reserved[8];
} EFI_ACPI_4_0_CORRECTED_PLATFORM_ERROR_POLLING_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT32 PollingInterval;
} EFI_ACPI_4_0_CPEP_PROCESSOR_APIC_SAPIC_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 OffsetProxDomInfo;
UINT32 MaximumNumberOfProximityDomains;
UINT32 MaximumNumberOfClockDomains;
UINT64 MaximumPhysicalAddress;
} EFI_ACPI_4_0_MAXIMUM_SYSTEM_CHARACTERISTICS_TABLE_HEADER;
typedef struct {
UINT8 Revision;
UINT8 Length;
UINT32 ProximityDomainRangeLow;
UINT32 ProximityDomainRangeHigh;
UINT32 MaximumProcessorCapacity;
UINT64 MaximumMemoryCapacity;
} EFI_ACPI_4_0_MAXIMUM_PROXIMITY_DOMAIN_INFORMATION_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 BootErrorRegionLength;
UINT64 BootErrorRegion;
} EFI_ACPI_4_0_BOOT_ERROR_RECORD_TABLE_HEADER;
typedef struct {
UINT32 UncorrectableErrorValid:1;
UINT32 CorrectableErrorValid:1;
UINT32 MultipleUncorrectableErrors:1;
UINT32 MultipleCorrectableErrors:1;
UINT32 ErrorDataEntryCount:10;
UINT32 Reserved:18;
} EFI_ACPI_4_0_ERROR_BLOCK_STATUS;

typedef struct {
EFI_ACPI_4_0_ERROR_BLOCK_STATUS BlockStatus;
UINT32 RawDataOffset;
UINT32 RawDataLength;
UINT32 DataLength;
UINT32 ErrorSeverity;
} EFI_ACPI_4_0_BOOT_ERROR_REGION_STRUCTURE;
typedef struct {
UINT8 SectionType[16];
UINT32 ErrorSeverity;
UINT16 Revision;
UINT8 ValidationBits;
UINT8 Flags;
UINT32 ErrorDataLength;
UINT8 FruId[16];
UINT8 FruText[20];
} EFI_ACPI_4_0_GENERIC_ERROR_DATA_ENTRY_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 ErrorSourceCount;
} EFI_ACPI_4_0_HARDWARE_ERROR_SOURCE_TABLE_HEADER;
typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT64 GlobalCapabilityInitData;
UINT64 GlobalControlInitData;
UINT8 NumberOfHardwareBanks;
UINT8 Reserved1[7];
} EFI_ACPI_4_0_IA32_ARCHITECTURE_MACHINE_CHECK_EXCEPTION_STRUCTURE;

typedef struct {
UINT8 BankNumber;
UINT8 ClearStatusOnInitialization;
UINT8 StatusDataFormat;
UINT8 Reserved0;
UINT32 ControlRegisterMsrAddress;
UINT64 ControlInitData;
UINT32 StatusRegisterMsrAddress;
UINT32 AddressRegisterMsrAddress;
UINT32 MiscRegisterMsrAddress;
} EFI_ACPI_4_0_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_BANK_STRUCTURE;
typedef struct {
UINT16 Type:1;
UINT16 PollInterval:1;
UINT16 SwitchToPollingThresholdValue:1;
UINT16 SwitchToPollingThresholdWindow:1;
UINT16 ErrorThresholdValue:1;
UINT16 ErrorThresholdWindow:1;
UINT16 Reserved:10;
} EFI_ACPI_4_0_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
EFI_ACPI_4_0_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE ConfigurationWriteEnable;
UINT32 PollInterval;
UINT32 Vector;
UINT32 SwitchToPollingThresholdValue;
UINT32 SwitchToPollingThresholdWindow;
UINT32 ErrorThresholdValue;
UINT32 ErrorThresholdWindow;
} EFI_ACPI_4_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
EFI_ACPI_4_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE NotificationStructure;
UINT8 NumberOfHardwareBanks;
UINT8 Reserved1[3];
} EFI_ACPI_4_0_IA32_ARCHITECTURE_CORRECTED_MACHINE_CHECK_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 MaxRawDataLength;
} EFI_ACPI_4_0_IA32_ARCHITECTURE_NMI_ERROR_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
UINT32 RootErrorCommand;
} EFI_ACPI_4_0_PCI_EXPRESS_ROOT_PORT_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_4_0_PCI_EXPRESS_DEVICE_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
UINT32 SecondaryUncorrectableErrorMask;
UINT32 SecondaryUncorrectableErrorSeverity;
UINT32 SecondaryAdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_4_0_PCI_EXPRESS_BRIDGE_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT16 RelatedSourceId;
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 MaxRawDataLength;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE ErrorStatusAddress;
EFI_ACPI_4_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE NotificationStructure;
UINT32 ErrorStatusBlockLength;
} EFI_ACPI_4_0_GENERIC_HARDWARE_ERROR_SOURCE_STRUCTURE;

typedef struct {
EFI_ACPI_4_0_ERROR_BLOCK_STATUS BlockStatus;
UINT32 RawDataOffset;
UINT32 RawDataLength;
UINT32 DataLength;
UINT32 ErrorSeverity;
} EFI_ACPI_4_0_GENERIC_ERROR_STATUS_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 SerializationHeaderSize;
UINT8 Reserved0[4];
UINT32 InstructionEntryCount;
} EFI_ACPI_4_0_ERROR_RECORD_SERIALIZATION_TABLE_HEADER;
typedef struct {
UINT8 SerializationAction;
UINT8 Instruction;
UINT8 Flags;
UINT8 Reserved0;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE RegisterRegion;
UINT64 Value;
UINT64 Mask;
} EFI_ACPI_4_0_ERST_SERIALIZATION_INSTRUCTION_ENTRY;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 InjectionHeaderSize;
UINT8 InjectionFlags;
UINT8 Reserved0[3];
UINT32 InjectionEntryCount;
} EFI_ACPI_4_0_ERROR_INJECTION_TABLE_HEADER;
typedef struct {
UINT8 InjectionAction;
UINT8 Instruction;
UINT8 Flags;
UINT8 Reserved0;
EFI_ACPI_4_0_GENERIC_ADDRESS_STRUCTURE RegisterRegion;
UINT64 Value;
UINT64 Mask;
} EFI_ACPI_4_0_EINJ_INJECTION_INSTRUCTION_ENTRY;

typedef struct {
UINT32 HeaderSize;
UINT32 Revision;
UINT32 TableSize;
UINT32 EntryCount;
} EFI_ACPI_4_0_EINJ_TRIGGER_ACTION_TABLE;
#pragma pack()
#pragma pack(1)

typedef struct {
ACPI_SMALL_RESOURCE_HEADER Header;
UINT16 DmaRequestLine;
UINT16 DmaChannel;
UINT8 DmaTransferWidth;
} EFI_ACPI_FIXED_DMA_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 RevisionId;
UINT8 ConnectionType;
UINT16 GeneralFlags;
UINT16 InterruptFlags;
UINT8 PinConfiguration;
UINT16 OutputDriveStrength;
UINT16 DebounceTimeout;
UINT16 PinTableOffset;
UINT8 ResourceSourceIndex;
UINT16 ResourceSourceNameOffset;
UINT16 VendorDataOffset;
UINT16 VendorDataLength;
} EFI_ACPI_GPIO_CONNECTION_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 RevisionId;
UINT8 ResourceSourceIndex;
UINT8 SerialBusType;
UINT8 GeneralFlags;
UINT16 TypeSpecificFlags;
UINT8 TypeSpecificRevisionId;
UINT16 TypeDataLength;

} EFI_ACPI_SERIAL_BUS_RESOURCE_DESCRIPTOR;
typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 RevisionId;
UINT8 ResourceSourceIndex;
UINT8 SerialBusType;
UINT8 GeneralFlags;
UINT16 TypeSpecificFlags;
UINT8 TypeSpecificRevisionId;
UINT16 TypeDataLength;
UINT32 ConnectionSpeed;
UINT16 SlaveAddress;
} EFI_ACPI_SERIAL_BUS_RESOURCE_I2C_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 RevisionId;
UINT8 ResourceSourceIndex;
UINT8 SerialBusType;
UINT8 GeneralFlags;
UINT16 TypeSpecificFlags;
UINT8 TypeSpecificRevisionId;
UINT16 TypeDataLength;
UINT32 ConnectionSpeed;
UINT8 DataBitLength;
UINT8 Phase;
UINT8 Polarity;
UINT16 DeviceSelection;
} EFI_ACPI_SERIAL_BUS_RESOURCE_SPI_DESCRIPTOR;

typedef struct {
ACPI_LARGE_RESOURCE_HEADER Header;
UINT8 RevisionId;
UINT8 ResourceSourceIndex;
UINT8 SerialBusType;
UINT8 GeneralFlags;
UINT16 TypeSpecificFlags;
UINT8 TypeSpecificRevisionId;
UINT16 TypeDataLength;
UINT32 DefaultBaudRate;
UINT16 RxFIFO;
UINT16 TxFIFO;
UINT8 Parity;
UINT8 SerialLinesEnabled;
} EFI_ACPI_SERIAL_BUS_RESOURCE_UART_DESCRIPTOR;

#pragma pack()

#pragma pack(1)

typedef struct {
UINT8 AddressSpaceId;
UINT8 RegisterBitWidth;
UINT8 RegisterBitOffset;
UINT8 AccessSize;
UINT64 Address;
} EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE;
typedef struct {
UINT64 Signature;
UINT8 Checksum;
UINT8 OemId[6];
UINT8 Revision;
UINT32 RsdtAddress;
UINT32 Length;
UINT64 XsdtAddress;
UINT8 ExtendedChecksum;
UINT8 Reserved[3];
} EFI_ACPI_5_0_ROOT_SYSTEM_DESCRIPTION_POINTER;
typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_5_0_COMMON_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 FirmwareCtrl;
UINT32 Dsdt;
UINT8 Reserved0;
UINT8 PreferredPmProfile;
UINT16 SciInt;
UINT32 SmiCmd;
UINT8 AcpiEnable;
UINT8 AcpiDisable;
UINT8 S4BiosReq;
UINT8 PstateCnt;
UINT32 Pm1aEvtBlk;
UINT32 Pm1bEvtBlk;
UINT32 Pm1aCntBlk;
UINT32 Pm1bCntBlk;
UINT32 Pm2CntBlk;
UINT32 PmTmrBlk;
UINT32 Gpe0Blk;
UINT32 Gpe1Blk;
UINT8 Pm1EvtLen;
UINT8 Pm1CntLen;
UINT8 Pm2CntLen;
UINT8 PmTmrLen;
UINT8 Gpe0BlkLen;
UINT8 Gpe1BlkLen;
UINT8 Gpe1Base;
UINT8 CstCnt;
UINT16 PLvl2Lat;
UINT16 PLvl3Lat;
UINT16 FlushSize;
UINT16 FlushStride;
UINT8 DutyOffset;
UINT8 DutyWidth;
UINT8 DayAlrm;
UINT8 MonAlrm;
UINT8 Century;
UINT16 IaPcBootArch;
UINT8 Reserved1;
UINT32 Flags;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE ResetReg;
UINT8 ResetValue;
UINT8 Reserved2[3];
UINT64 XFirmwareCtrl;
UINT64 XDsdt;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPm1aEvtBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPm1bEvtBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPm1aCntBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPm1bCntBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPm2CntBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XPmTmrBlk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XGpe0Blk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE XGpe1Blk;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE SleepControlReg;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE SleepStatusReg;
} EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE;
typedef struct {
UINT32 Signature;
UINT32 Length;
UINT32 HardwareSignature;
UINT32 FirmwareWakingVector;
UINT32 GlobalLock;
UINT32 Flags;
UINT64 XFirmwareWakingVector;
UINT8 Version;
UINT8 Reserved0[3];
UINT32 OspmFlags;
UINT8 Reserved1[24];
} EFI_ACPI_5_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 LocalApicAddress;
UINT32 Flags;
} EFI_ACPI_5_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 ApicId;
UINT32 Flags;
} EFI_ACPI_5_0_PROCESSOR_LOCAL_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 IoApicAddress;
UINT32 GlobalSystemInterruptBase;
} EFI_ACPI_5_0_IO_APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Bus;
UINT8 Source;
UINT32 GlobalSystemInterrupt;
UINT16 Flags;
} EFI_ACPI_5_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
UINT8 CpeiProcessorOverride;
UINT8 Reserved[31];
} EFI_ACPI_5_0_PLATFORM_INTERRUPT_APIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 GlobalSystemInterrupt;
} EFI_ACPI_5_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT16 Flags;
UINT8 LocalApicLint;
} EFI_ACPI_5_0_LOCAL_APIC_NMI_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved;
UINT64 LocalApicAddress;
} EFI_ACPI_5_0_LOCAL_APIC_ADDRESS_OVERRIDE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 IoApicId;
UINT8 Reserved;
UINT32 GlobalSystemInterruptBase;
UINT64 IoSapicAddress;
} EFI_ACPI_5_0_IO_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 AcpiProcessorId;
UINT8 LocalSapicId;
UINT8 LocalSapicEid;
UINT8 Reserved[3];
UINT32 Flags;
UINT32 ACPIProcessorUIDValue;
} EFI_ACPI_5_0_PROCESSOR_LOCAL_SAPIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT8 InterruptType;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT8 IoSapicVector;
UINT32 GlobalSystemInterrupt;
UINT32 PlatformInterruptSourceFlags;
} EFI_ACPI_5_0_PLATFORM_INTERRUPT_SOURCES_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Reserved[2];
UINT32 X2ApicId;
UINT32 Flags;
UINT32 AcpiProcessorUid;
} EFI_ACPI_5_0_PROCESSOR_LOCAL_X2APIC_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Flags;
UINT32 AcpiProcessorUid;
UINT8 LocalX2ApicLint;
UINT8 Reserved[3];
} EFI_ACPI_5_0_LOCAL_X2APIC_NMI_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved;
UINT32 GicId;
UINT32 AcpiProcessorUid;
UINT32 Flags;
UINT32 ParkingProtocolVersion;
UINT32 PerformanceInterruptGsiv;
UINT64 ParkedAddress;
UINT64 PhysicalBaseAddress;
} EFI_ACPI_5_0_GIC_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT16 Reserved1;
UINT32 GicId;
UINT64 PhysicalBaseAddress;
UINT32 SystemVectorBase;
UINT32 Reserved2;
} EFI_ACPI_5_0_GIC_DISTRIBUTOR_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 WarningEnergyLevel;
UINT32 LowEnergyLevel;
UINT32 CriticalEnergyLevel;
} EFI_ACPI_5_0_SMART_BATTERY_DESCRIPTION_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE EcControl;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE EcData;
UINT32 Uid;
UINT8 GpeBit;
} EFI_ACPI_5_0_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 Reserved1;
UINT64 Reserved2;
} EFI_ACPI_5_0_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 ProximityDomain7To0;
UINT8 ApicId;
UINT32 Flags;
UINT8 LocalSapicEid;
UINT8 ProximityDomain31To8[3];
UINT32 ClockDomain;
} EFI_ACPI_5_0_PROCESSOR_LOCAL_APIC_SAPIC_AFFINITY_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT32 ProximityDomain;
UINT16 Reserved1;
UINT32 AddressBaseLow;
UINT32 AddressBaseHigh;
UINT32 LengthLow;
UINT32 LengthHigh;
UINT32 Reserved2;
UINT32 Flags;
UINT64 Reserved3;
} EFI_ACPI_5_0_MEMORY_AFFINITY_STRUCTURE;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Reserved1[2];
UINT32 ProximityDomain;
UINT32 X2ApicId;
UINT32 Flags;
UINT32 ClockDomain;
UINT8 Reserved2[4];
} EFI_ACPI_5_0_PROCESSOR_LOCAL_X2APIC_AFFINITY_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT64 NumberOfSystemLocalities;
} EFI_ACPI_5_0_SYSTEM_LOCALITY_DISTANCE_INFORMATION_TABLE_HEADER;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT8 Reserved[8];
} EFI_ACPI_5_0_CORRECTED_PLATFORM_ERROR_POLLING_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 ProcessorId;
UINT8 ProcessorEid;
UINT32 PollingInterval;
} EFI_ACPI_5_0_CPEP_PROCESSOR_APIC_SAPIC_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 OffsetProxDomInfo;
UINT32 MaximumNumberOfProximityDomains;
UINT32 MaximumNumberOfClockDomains;
UINT64 MaximumPhysicalAddress;
} EFI_ACPI_5_0_MAXIMUM_SYSTEM_CHARACTERISTICS_TABLE_HEADER;
typedef struct {
UINT8 Revision;
UINT8 Length;
UINT32 ProximityDomainRangeLow;
UINT32 ProximityDomainRangeHigh;
UINT32 MaximumProcessorCapacity;
UINT64 MaximumMemoryCapacity;
} EFI_ACPI_5_0_MAXIMUM_PROXIMITY_DOMAIN_INFORMATION_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT8 PlatformCommunicationChannelIdentifier[12];
} EFI_ACPI_5_0_RAS_FEATURE_TABLE;
typedef struct {
UINT32 Signature;
UINT16 Command;
UINT16 Status;
UINT16 Version;
UINT8 RASCapabilities[16];
UINT8 SetRASCapabilities[16];
UINT16 NumberOfRASFParameterBlocks;
UINT32 SetRASCapabilitiesStatus;
} EFI_ACPI_5_0_RASF_PLATFORM_COMMUNICATION_CHANNEL_SHARED_MEMORY_REGION;
typedef struct {
UINT16 Type;
UINT16 Version;
UINT16 Length;
UINT16 PatrolScrubCommand;
UINT64 RequestedAddressRange[2];
UINT64 ActualAddressRange[2];
UINT16 Flags;
UINT8 RequestedSpeed;
} EFI_ACPI_5_0_RASF_PATROL_SCRUB_PLATFORM_BLOCK_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT8 PlatformCommunicationChannelIdentifier;
UINT8 Reserved[3];

} EFI_ACPI_5_0_MEMORY_POWER_STATUS_TABLE;
typedef struct {
UINT32 Signature;
UINT16 Command;
UINT16 Status;
UINT32 MemoryPowerCommandRegister;
UINT32 MemoryPowerStatusRegister;
UINT32 PowerStateId;
UINT32 MemoryPowerNodeId;
UINT64 MemoryEnergyConsumed;
UINT64 ExpectedAveragePowerComsuned;
} EFI_ACPI_5_0_MPST_PLATFORM_COMMUNICATION_CHANNEL_SHARED_MEMORY_REGION;
typedef struct {
UINT8 PowerStateValue;
UINT8 PowerStateInformationIndex;
} EFI_ACPI_5_0_MPST_MEMORY_POWER_STATE;

typedef struct {
UINT8 Flag;
UINT8 Reserved;
UINT16 MemoryPowerNodeId;
UINT32 Length;
UINT64 AddressBase;
UINT64 AddressLength;
UINT32 NumberOfPowerStates;
UINT32 NumberOfPhysicalComponents;

} EFI_ACPI_5_0_MPST_MEMORY_POWER_STRUCTURE;

typedef struct {
UINT16 MemoryPowerNodeCount;
UINT8 Reserved[2];
} EFI_ACPI_5_0_MPST_MEMORY_POWER_NODE_TABLE;

typedef struct {
UINT8 PowerStateStructureID;
UINT8 Flag;
UINT16 Reserved;
UINT32 AveragePowerConsumedInMPS0;
UINT32 RelativePowerSavingToMPS0;
UINT64 ExitLatencyToMPS0;
} EFI_ACPI_5_0_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_STRUCTURE;

typedef struct {
UINT16 MemoryPowerStateCharacteristicsCount;
UINT8 Reserved[2];
} EFI_ACPI_5_0_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_TABLE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 Reserved;
} EFI_ACPI_5_0_MEMORY_TOPOLOGY_TABLE;
typedef struct {
UINT8 Type;
UINT8 Reserved;
UINT16 Length;
UINT16 Flags;
UINT16 Reserved1;
} EFI_ACPI_5_0_PMMT_COMMON_MEMORY_AGGREGATOR_DEVICE_STRUCTURE;
typedef struct {
EFI_ACPI_5_0_PMMT_COMMON_MEMORY_AGGREGATOR_DEVICE_STRUCTURE Header;

} EFI_ACPI_5_0_PMMT_SOCKET_MEMORY_AGGREGATOR_DEVICE_STRUCTURE;

typedef struct {
EFI_ACPI_5_0_PMMT_COMMON_MEMORY_AGGREGATOR_DEVICE_STRUCTURE Header;
UINT32 ReadLatency;
UINT32 WriteLatency;
UINT32 ReadBandwidth;
UINT32 WriteBandwidth;
UINT16 OptimalAccessUnit;
UINT16 OptimalAccessAlignment;
UINT16 Reserved;
UINT16 NumberOfProximityDomains;

} EFI_ACPI_5_0_PMMT_MEMORY_CONTROLLER_MEMORY_AGGREGATOR_DEVICE_STRUCTURE;

typedef struct {
EFI_ACPI_5_0_PMMT_COMMON_MEMORY_AGGREGATOR_DEVICE_STRUCTURE Header;
UINT16 PhysicalComponentIdentifier;
UINT16 Reserved;
UINT32 SizeOfDimm;
UINT32 SmbiosHandle;
} EFI_ACPI_5_0_PMMT_DIMM_MEMORY_AGGREGATOR_DEVICE_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;

UINT16 Version;

UINT8 Status;

UINT8 ImageType;

UINT64 ImageAddress;

UINT32 ImageOffsetX;

UINT32 ImageOffsetY;
} EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE;
typedef struct {
UINT16 Type;
UINT8 Length;
UINT8 Revision;
} EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER;

typedef struct {
UINT32 Signature;
UINT32 Length;
} EFI_ACPI_5_0_FPDT_PERFORMANCE_TABLE_HEADER;

typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER Header;
UINT32 Reserved;

UINT64 BootPerformanceTablePointer;
} EFI_ACPI_5_0_FPDT_BOOT_PERFORMANCE_TABLE_POINTER_RECORD;

typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER Header;
UINT32 Reserved;

UINT64 S3PerformanceTablePointer;
} EFI_ACPI_5_0_FPDT_S3_PERFORMANCE_TABLE_POINTER_RECORD;

typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER Header;
UINT32 Reserved;

UINT64 ResetEnd;

UINT64 OsLoaderLoadImageStart;

UINT64 OsLoaderStartImageStart;

UINT64 ExitBootServicesEntry;

UINT64 ExitBootServicesExit;
} EFI_ACPI_5_0_FPDT_FIRMWARE_BASIC_BOOT_RECORD;
typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_TABLE_HEADER Header;

} EFI_ACPI_5_0_FPDT_FIRMWARE_BASIC_BOOT_TABLE;
typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_TABLE_HEADER Header;

} EFI_ACPI_5_0_FPDT_FIRMWARE_S3_BOOT_TABLE;

typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER Header;

UINT32 ResumeCount;

UINT64 FullResume;

UINT64 AverageResume;
} EFI_ACPI_5_0_FPDT_S3_RESUME_RECORD;

typedef struct {
EFI_ACPI_5_0_FPDT_PERFORMANCE_RECORD_HEADER Header;

UINT64 SuspendStart;

UINT64 SuspendEnd;
} EFI_ACPI_5_0_FPDT_S3_SUSPEND_RECORD;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
} EFI_ACPI_5_0_FIRMWARE_PERFORMANCE_RECORD_TABLE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT64 PhysicalAddress;
UINT32 GlobalFlags;
UINT32 SecurePL1TimerGSIV;
UINT32 SecurePL1TimerFlags;
UINT32 NonSecurePL1TimerGSIV;
UINT32 NonSecurePL1TimerFlags;
UINT32 VirtualTimerGSIV;
UINT32 VirtualTimerFlags;
UINT32 NonSecurePL2TimerGSIV;
UINT32 NonSecurePL2TimerFlags;
} EFI_ACPI_5_0_GENERIC_TIMER_DESCRIPTION_TABLE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 BootErrorRegionLength;
UINT64 BootErrorRegion;
} EFI_ACPI_5_0_BOOT_ERROR_RECORD_TABLE_HEADER;
typedef struct {
UINT32 UncorrectableErrorValid:1;
UINT32 CorrectableErrorValid:1;
UINT32 MultipleUncorrectableErrors:1;
UINT32 MultipleCorrectableErrors:1;
UINT32 ErrorDataEntryCount:10;
UINT32 Reserved:18;
} EFI_ACPI_5_0_ERROR_BLOCK_STATUS;

typedef struct {
EFI_ACPI_5_0_ERROR_BLOCK_STATUS BlockStatus;
UINT32 RawDataOffset;
UINT32 RawDataLength;
UINT32 DataLength;
UINT32 ErrorSeverity;
} EFI_ACPI_5_0_BOOT_ERROR_REGION_STRUCTURE;
typedef struct {
UINT8 SectionType[16];
UINT32 ErrorSeverity;
UINT16 Revision;
UINT8 ValidationBits;
UINT8 Flags;
UINT32 ErrorDataLength;
UINT8 FruId[16];
UINT8 FruText[20];
} EFI_ACPI_5_0_GENERIC_ERROR_DATA_ENTRY_STRUCTURE;
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 ErrorSourceCount;
} EFI_ACPI_5_0_HARDWARE_ERROR_SOURCE_TABLE_HEADER;
typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT64 GlobalCapabilityInitData;
UINT64 GlobalControlInitData;
UINT8 NumberOfHardwareBanks;
UINT8 Reserved1[7];
} EFI_ACPI_5_0_IA32_ARCHITECTURE_MACHINE_CHECK_EXCEPTION_STRUCTURE;

typedef struct {
UINT8 BankNumber;
UINT8 ClearStatusOnInitialization;
UINT8 StatusDataFormat;
UINT8 Reserved0;
UINT32 ControlRegisterMsrAddress;
UINT64 ControlInitData;
UINT32 StatusRegisterMsrAddress;
UINT32 AddressRegisterMsrAddress;
UINT32 MiscRegisterMsrAddress;
} EFI_ACPI_5_0_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_BANK_STRUCTURE;
typedef struct {
UINT16 Type:1;
UINT16 PollInterval:1;
UINT16 SwitchToPollingThresholdValue:1;
UINT16 SwitchToPollingThresholdWindow:1;
UINT16 ErrorThresholdValue:1;
UINT16 ErrorThresholdWindow:1;
UINT16 Reserved:10;
} EFI_ACPI_5_0_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE;

typedef struct {
UINT8 Type;
UINT8 Length;
EFI_ACPI_5_0_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE ConfigurationWriteEnable;
UINT32 PollInterval;
UINT32 Vector;
UINT32 SwitchToPollingThresholdValue;
UINT32 SwitchToPollingThresholdWindow;
UINT32 ErrorThresholdValue;
UINT32 ErrorThresholdWindow;
} EFI_ACPI_5_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
EFI_ACPI_5_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE NotificationStructure;
UINT8 NumberOfHardwareBanks;
UINT8 Reserved1[3];
} EFI_ACPI_5_0_IA32_ARCHITECTURE_CORRECTED_MACHINE_CHECK_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 MaxRawDataLength;
} EFI_ACPI_5_0_IA32_ARCHITECTURE_NMI_ERROR_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
UINT32 RootErrorCommand;
} EFI_ACPI_5_0_PCI_EXPRESS_ROOT_PORT_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_5_0_PCI_EXPRESS_DEVICE_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT8 Reserved0[2];
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 Bus;
UINT16 Device;
UINT16 Function;
UINT16 DeviceControl;
UINT8 Reserved1[2];
UINT32 UncorrectableErrorMask;
UINT32 UncorrectableErrorSeverity;
UINT32 CorrectableErrorMask;
UINT32 AdvancedErrorCapabilitiesAndControl;
UINT32 SecondaryUncorrectableErrorMask;
UINT32 SecondaryUncorrectableErrorSeverity;
UINT32 SecondaryAdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_5_0_PCI_EXPRESS_BRIDGE_AER_STRUCTURE;

typedef struct {
UINT16 Type;
UINT16 SourceId;
UINT16 RelatedSourceId;
UINT8 Flags;
UINT8 Enabled;
UINT32 NumberOfRecordsToPreAllocate;
UINT32 MaxSectionsPerRecord;
UINT32 MaxRawDataLength;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE ErrorStatusAddress;
EFI_ACPI_5_0_HARDWARE_ERROR_NOTIFICATION_STRUCTURE NotificationStructure;
UINT32 ErrorStatusBlockLength;
} EFI_ACPI_5_0_GENERIC_HARDWARE_ERROR_SOURCE_STRUCTURE;

typedef struct {
EFI_ACPI_5_0_ERROR_BLOCK_STATUS BlockStatus;
UINT32 RawDataOffset;
UINT32 RawDataLength;
UINT32 DataLength;
UINT32 ErrorSeverity;
} EFI_ACPI_5_0_GENERIC_ERROR_STATUS_STRUCTURE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 SerializationHeaderSize;
UINT8 Reserved0[4];
UINT32 InstructionEntryCount;
} EFI_ACPI_5_0_ERROR_RECORD_SERIALIZATION_TABLE_HEADER;
typedef struct {
UINT8 SerializationAction;
UINT8 Instruction;
UINT8 Flags;
UINT8 Reserved0;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE RegisterRegion;
UINT64 Value;
UINT64 Mask;
} EFI_ACPI_5_0_ERST_SERIALIZATION_INSTRUCTION_ENTRY;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 InjectionHeaderSize;
UINT8 InjectionFlags;
UINT8 Reserved0[3];
UINT32 InjectionEntryCount;
} EFI_ACPI_5_0_ERROR_INJECTION_TABLE_HEADER;
typedef struct {
UINT8 InjectionAction;
UINT8 Instruction;
UINT8 Flags;
UINT8 Reserved0;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE RegisterRegion;
UINT64 Value;
UINT64 Mask;
} EFI_ACPI_5_0_EINJ_INJECTION_INSTRUCTION_ENTRY;

typedef struct {
UINT32 HeaderSize;
UINT32 Revision;
UINT32 TableSize;
UINT32 EntryCount;
} EFI_ACPI_5_0_EINJ_TRIGGER_ACTION_TABLE;

typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
UINT32 Flags;
UINT64 Reserved;
} EFI_ACPI_5_0_PLATFORM_COMMUNICATION_CHANNEL_TABLE_HEADER;
typedef struct {
UINT8 Type;
UINT8 Length;
} EFI_ACPI_5_0_PCCT_SUBSPACE_HEADER;

typedef struct {
UINT8 Type;
UINT8 Length;
UINT8 Reserved[6];
UINT64 BaseAddress;
UINT64 AddressLength;
EFI_ACPI_5_0_GENERIC_ADDRESS_STRUCTURE DoorbellRegister;
UINT64 DoorbellPreserve;
UINT64 DoorbellWrite;
UINT32 NominalLatency;
UINT32 MaximumPeriodicAccessRate;
UINT16 MinimumRequestTurnaroundTime;
} EFI_ACPI_5_0_PCCT_SUBSPACE_GENERIC;

typedef struct {
UINT8 Command;
UINT8 Reserved:7;
UINT8 GenerateSci:1;
} EFI_ACPI_5_0_PCCT_GENERIC_SHARED_MEMORY_REGION_COMMAND;

typedef struct {
UINT8 CommandComplete:1;
UINT8 SciDoorbell:1;
UINT8 Error:1;
UINT8 Reserved:5;
UINT8 Reserved1;
} EFI_ACPI_5_0_PCCT_GENERIC_SHARED_MEMORY_REGION_STATUS;

typedef struct {
UINT32 Signature;
EFI_ACPI_5_0_PCCT_GENERIC_SHARED_MEMORY_REGION_COMMAND Command;
EFI_ACPI_5_0_PCCT_GENERIC_SHARED_MEMORY_REGION_STATUS Status;
} EFI_ACPI_5_0_PCCT_GENERIC_SHARED_MEMORY_REGION_HEADER;
#pragma pack()

#pragma pack(1)
typedef struct {
EFI_ACPI_DESCRIPTION_HEADER Header;
GUID Identifier;
UINT16 DataOffset;
} EFI_ACPI_DATA_TABLE;

typedef struct {
EFI_ACPI_DATA_TABLE UefiAcpiDataTable;
UINT32 SwSmiNumber;
UINT64 BufferPtrAddress;
} EFI_SMM_COMMUNICATION_ACPI_TABLE;

typedef struct _ {

EFI_GUID HeaderGuid;

UINTN MessageLength;

UINT8 Data[1];
} EFI_SMM_COMMUNICATE_HEADER;

#pragma pack()

typedef struct _EFI_SMM_COMMUNICATION_PROTOCOL EFI_SMM_COMMUNICATION_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_COMMUNICATE2)(
EFI_SMM_COMMUNICATION_PROTOCOL *This,
void *CommBuffer,
UINTN *CommSize
);

struct _EFI_SMM_COMMUNICATION_PROTOCOL {
EFI_SMM_COMMUNICATE2 Communicate;
};

extern EFI_GUID gEfiSmmCommunicationProtocolGuid;
typedef struct _EFI_SMM_RESERVED_SMRAM_REGION {

EFI_PHYSICAL_ADDRESS SmramReservedStart;

UINT64 SmramReservedSize;
} EFI_SMM_RESERVED_SMRAM_REGION;

typedef struct _EFI_SMM_CONFIGURATION_PROTOCOL EFI_SMM_CONFIGURATION_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_REGISTER_SMM_ENTRY)(
EFI_SMM_CONFIGURATION_PROTOCOL *This,
EFI_SMM_ENTRY_POINT SmmEntryPoint
);
struct _EFI_SMM_CONFIGURATION_PROTOCOL {

EFI_SMM_RESERVED_SMRAM_REGION *SmramReservedRegions;
EFI_SMM_REGISTER_SMM_ENTRY RegisterSmmEntry;
};

extern EFI_GUID gEfiSmmConfigurationProtocolGuid;

typedef struct _EFI_SMM_CONTROL2_PROTOCOL EFI_SMM_CONTROL2_PROTOCOL;
typedef UINTN EFI_SMM_PERIOD;
typedef
EFI_STATUS
( *EFI_SMM_ACTIVATE2)(
EFI_SMM_CONTROL2_PROTOCOL *This,
UINT8 *CommandPort ,
UINT8 *DataPort ,
BOOLEAN Periodic ,
UINTN ActivationInterval
);
typedef
EFI_STATUS
( *EFI_SMM_DEACTIVATE2)(
EFI_SMM_CONTROL2_PROTOCOL *This,
BOOLEAN Periodic
);

struct _EFI_SMM_CONTROL2_PROTOCOL {
EFI_SMM_ACTIVATE2 Trigger;
EFI_SMM_DEACTIVATE2 Clear;

EFI_SMM_PERIOD MinimumTriggerPeriod;
};

extern EFI_GUID gEfiSmmControl2ProtocolGuid;
typedef enum {

EFI_SMM_SAVE_STATE_REGISTER_GDTBASE = 4,
EFI_SMM_SAVE_STATE_REGISTER_IDTBASE = 5,
EFI_SMM_SAVE_STATE_REGISTER_LDTBASE = 6,
EFI_SMM_SAVE_STATE_REGISTER_GDTLIMIT = 7,
EFI_SMM_SAVE_STATE_REGISTER_IDTLIMIT = 8,
EFI_SMM_SAVE_STATE_REGISTER_LDTLIMIT = 9,
EFI_SMM_SAVE_STATE_REGISTER_LDTINFO = 10,
EFI_SMM_SAVE_STATE_REGISTER_ES = 20,
EFI_SMM_SAVE_STATE_REGISTER_CS = 21,
EFI_SMM_SAVE_STATE_REGISTER_SS = 22,
EFI_SMM_SAVE_STATE_REGISTER_DS = 23,
EFI_SMM_SAVE_STATE_REGISTER_FS = 24,
EFI_SMM_SAVE_STATE_REGISTER_GS = 25,
EFI_SMM_SAVE_STATE_REGISTER_LDTR_SEL = 26,
EFI_SMM_SAVE_STATE_REGISTER_TR_SEL = 27,
EFI_SMM_SAVE_STATE_REGISTER_DR7 = 28,
EFI_SMM_SAVE_STATE_REGISTER_DR6 = 29,
EFI_SMM_SAVE_STATE_REGISTER_R8 = 30,
EFI_SMM_SAVE_STATE_REGISTER_R9 = 31,
EFI_SMM_SAVE_STATE_REGISTER_R10 = 32,
EFI_SMM_SAVE_STATE_REGISTER_R11 = 33,
EFI_SMM_SAVE_STATE_REGISTER_R12 = 34,
EFI_SMM_SAVE_STATE_REGISTER_R13 = 35,
EFI_SMM_SAVE_STATE_REGISTER_R14 = 36,
EFI_SMM_SAVE_STATE_REGISTER_R15 = 37,
EFI_SMM_SAVE_STATE_REGISTER_RAX = 38,
EFI_SMM_SAVE_STATE_REGISTER_RBX = 39,
EFI_SMM_SAVE_STATE_REGISTER_RCX = 40,
EFI_SMM_SAVE_STATE_REGISTER_RDX = 41,
EFI_SMM_SAVE_STATE_REGISTER_RSP = 42,
EFI_SMM_SAVE_STATE_REGISTER_RBP = 43,
EFI_SMM_SAVE_STATE_REGISTER_RSI = 44,
EFI_SMM_SAVE_STATE_REGISTER_RDI = 45,
EFI_SMM_SAVE_STATE_REGISTER_RIP = 46,
EFI_SMM_SAVE_STATE_REGISTER_RFLAGS = 51,
EFI_SMM_SAVE_STATE_REGISTER_CR0 = 52,
EFI_SMM_SAVE_STATE_REGISTER_CR3 = 53,
EFI_SMM_SAVE_STATE_REGISTER_CR4 = 54,
EFI_SMM_SAVE_STATE_REGISTER_FCW = 256,
EFI_SMM_SAVE_STATE_REGISTER_FSW = 257,
EFI_SMM_SAVE_STATE_REGISTER_FTW = 258,
EFI_SMM_SAVE_STATE_REGISTER_OPCODE = 259,
EFI_SMM_SAVE_STATE_REGISTER_FP_EIP = 260,
EFI_SMM_SAVE_STATE_REGISTER_FP_CS = 261,
EFI_SMM_SAVE_STATE_REGISTER_DATAOFFSET = 262,
EFI_SMM_SAVE_STATE_REGISTER_FP_DS = 263,
EFI_SMM_SAVE_STATE_REGISTER_MM0 = 264,
EFI_SMM_SAVE_STATE_REGISTER_MM1 = 265,
EFI_SMM_SAVE_STATE_REGISTER_MM2 = 266,
EFI_SMM_SAVE_STATE_REGISTER_MM3 = 267,
EFI_SMM_SAVE_STATE_REGISTER_MM4 = 268,
EFI_SMM_SAVE_STATE_REGISTER_MM5 = 269,
EFI_SMM_SAVE_STATE_REGISTER_MM6 = 270,
EFI_SMM_SAVE_STATE_REGISTER_MM7 = 271,
EFI_SMM_SAVE_STATE_REGISTER_XMM0 = 272,
EFI_SMM_SAVE_STATE_REGISTER_XMM1 = 273,
EFI_SMM_SAVE_STATE_REGISTER_XMM2 = 274,
EFI_SMM_SAVE_STATE_REGISTER_XMM3 = 275,
EFI_SMM_SAVE_STATE_REGISTER_XMM4 = 276,
EFI_SMM_SAVE_STATE_REGISTER_XMM5 = 277,
EFI_SMM_SAVE_STATE_REGISTER_XMM6 = 278,
EFI_SMM_SAVE_STATE_REGISTER_XMM7 = 279,
EFI_SMM_SAVE_STATE_REGISTER_XMM8 = 280,
EFI_SMM_SAVE_STATE_REGISTER_XMM9 = 281,
EFI_SMM_SAVE_STATE_REGISTER_XMM10 = 282,
EFI_SMM_SAVE_STATE_REGISTER_XMM11 = 283,
EFI_SMM_SAVE_STATE_REGISTER_XMM12 = 284,
EFI_SMM_SAVE_STATE_REGISTER_XMM13 = 285,
EFI_SMM_SAVE_STATE_REGISTER_XMM14 = 286,
EFI_SMM_SAVE_STATE_REGISTER_XMM15 = 287,

EFI_SMM_SAVE_STATE_REGISTER_IO = 512,
EFI_SMM_SAVE_STATE_REGISTER_LMA = 513,
EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID = 514
} EFI_SMM_SAVE_STATE_REGISTER;
typedef enum {
EFI_SMM_SAVE_STATE_IO_WIDTH_UINT8 = 0,
EFI_SMM_SAVE_STATE_IO_WIDTH_UINT16 = 1,
EFI_SMM_SAVE_STATE_IO_WIDTH_UINT32 = 2,
EFI_SMM_SAVE_STATE_IO_WIDTH_UINT64 = 3
} EFI_SMM_SAVE_STATE_IO_WIDTH;

typedef enum {
EFI_SMM_SAVE_STATE_IO_TYPE_INPUT = 1,
EFI_SMM_SAVE_STATE_IO_TYPE_OUTPUT = 2,
EFI_SMM_SAVE_STATE_IO_TYPE_STRING = 4,
EFI_SMM_SAVE_STATE_IO_TYPE_REP_PREFIX = 8
} EFI_SMM_SAVE_STATE_IO_TYPE;
typedef struct _EFI_SMM_SAVE_STATE_IO_INFO {

UINT64 IoData;

UINT16 IoPort;

EFI_SMM_SAVE_STATE_IO_WIDTH IoWidth;

EFI_SMM_SAVE_STATE_IO_TYPE IoType;
} EFI_SMM_SAVE_STATE_IO_INFO;

typedef struct _EFI_SMM_CPU_PROTOCOL EFI_SMM_CPU_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_READ_SAVE_STATE)(
EFI_SMM_CPU_PROTOCOL *This,
UINTN Width,
EFI_SMM_SAVE_STATE_REGISTER Register,
UINTN CpuIndex,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_SMM_WRITE_SAVE_STATE)(
EFI_SMM_CPU_PROTOCOL *This,
UINTN Width,
EFI_SMM_SAVE_STATE_REGISTER Register,
UINTN CpuIndex,
void *Buffer
);
struct _EFI_SMM_CPU_PROTOCOL {
EFI_SMM_READ_SAVE_STATE ReadSaveState;
EFI_SMM_WRITE_SAVE_STATE WriteSaveState;
};

extern EFI_GUID gEfiSmmCpuProtocolGuid;

typedef struct {

UINT64 GpiNum;
} EFI_SMM_GPI_REGISTER_CONTEXT;

typedef struct _EFI_SMM_GPI_DISPATCH2_PROTOCOL EFI_SMM_GPI_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_GPI_REGISTER2)(
EFI_SMM_GPI_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_GPI_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_GPI_UNREGISTER2)(
EFI_SMM_GPI_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_GPI_DISPATCH2_PROTOCOL {
EFI_SMM_GPI_REGISTER2 Register;
EFI_SMM_GPI_UNREGISTER2 UnRegister;

UINTN NumSupportedGpis;
};

extern EFI_GUID gEfiSmmGpiDispatch2ProtocolGuid;
typedef enum {
WriteTrap,
ReadTrap,
ReadWriteTrap,
IoTrapTypeMaximum
} EFI_SMM_IO_TRAP_DISPATCH_TYPE;

typedef struct {
UINT16 Address;
UINT16 Length;
EFI_SMM_IO_TRAP_DISPATCH_TYPE Type;
} EFI_SMM_IO_TRAP_REGISTER_CONTEXT;

typedef struct {
UINT32 WriteData;
} EFI_SMM_IO_TRAP_CONTEXT;

typedef struct _EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_IO_TRAP_DISPATCH2_REGISTER)(
EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_IO_TRAP_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_IO_TRAP_DISPATCH2_UNREGISTER)(
EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL {
EFI_SMM_IO_TRAP_DISPATCH2_REGISTER Register;
EFI_SMM_IO_TRAP_DISPATCH2_UNREGISTER UnRegister;
};

extern EFI_GUID gEfiSmmIoTrapDispatch2ProtocolGuid;
typedef EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL EFI_SMM_PCI_ROOT_BRIDGE_IO_PROTOCOL;

extern EFI_GUID gEfiSmmPciRootBridgeIoProtocolGuid;
typedef struct {

UINT64 Period;

UINT64 SmiTickInterval;
} EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT;

typedef struct {

UINT64 ElapsedTime;
} EFI_SMM_PERIODIC_TIMER_CONTEXT;

typedef struct _EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_PERIODIC_TIMER_REGISTER2)(
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_PERIODIC_TIMER_UNREGISTER2)(
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_PERIODIC_TIMER_INTERVAL2)(
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *This,
UINT64 **SmiTickInterval
);

struct _EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL {
EFI_SMM_PERIODIC_TIMER_REGISTER2 Register;
EFI_SMM_PERIODIC_TIMER_UNREGISTER2 UnRegister;
EFI_SMM_PERIODIC_TIMER_INTERVAL2 GetNextShorterInterval;
};

extern EFI_GUID gEfiSmmPeriodicTimerDispatch2ProtocolGuid;
typedef enum {
EfiPowerButtonEntry,
EfiPowerButtonExit,
EfiPowerButtonMax
} EFI_POWER_BUTTON_PHASE;

typedef struct {

EFI_POWER_BUTTON_PHASE Phase;
} EFI_SMM_POWER_BUTTON_REGISTER_CONTEXT;

typedef struct _EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_POWER_BUTTON_REGISTER2)(
EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_POWER_BUTTON_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_POWER_BUTTON_UNREGISTER2)(
EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL {
EFI_SMM_POWER_BUTTON_REGISTER2 Register;
EFI_SMM_POWER_BUTTON_UNREGISTER2 UnRegister;
};

extern EFI_GUID gEfiSmmPowerButtonDispatch2ProtocolGuid;
extern EFI_GUID gEfiSmmReadyToLockProtocolGuid;
typedef
EFI_STATUS
( *EFI_SMM_RSC_HANDLER_CALLBACK)(
EFI_STATUS_CODE_TYPE CodeType,
EFI_STATUS_CODE_VALUE Value,
UINT32 Instance,
EFI_GUID *CallerId,
EFI_STATUS_CODE_DATA *Data
);
typedef
EFI_STATUS
( *EFI_SMM_RSC_HANDLER_REGISTER)(
EFI_SMM_RSC_HANDLER_CALLBACK Callback
);
typedef
EFI_STATUS
( *EFI_SMM_RSC_HANDLER_UNREGISTER)(
EFI_SMM_RSC_HANDLER_CALLBACK Callback
);

typedef struct _EFI_SMM_RSC_HANDLER_PROTOCOL {
EFI_SMM_RSC_HANDLER_REGISTER Register;
EFI_SMM_RSC_HANDLER_UNREGISTER Unregister;
} EFI_SMM_RSC_HANDLER_PROTOCOL;

extern EFI_GUID gEfiSmmRscHandlerProtocolGuid;
typedef enum {
EfiStandbyButtonEntry,
EfiStandbyButtonExit,
EfiStandbyButtonMax
} EFI_STANDBY_BUTTON_PHASE;

typedef struct {

EFI_STANDBY_BUTTON_PHASE Phase;
} EFI_SMM_STANDBY_BUTTON_REGISTER_CONTEXT;

typedef struct _EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_STANDBY_BUTTON_REGISTER2)(
EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_STANDBY_BUTTON_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_STANDBY_BUTTON_UNREGISTER2)(
EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL {
EFI_SMM_STANDBY_BUTTON_REGISTER2 Register;
EFI_SMM_STANDBY_BUTTON_UNREGISTER2 UnRegister;
};

extern EFI_GUID gEfiSmmStandbyButtonDispatch2ProtocolGuid;
typedef struct _EFI_SMM_STATUS_CODE_PROTOCOL EFI_SMM_STATUS_CODE_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_REPORT_STATUS_CODE)(
EFI_SMM_STATUS_CODE_PROTOCOL *This,
EFI_STATUS_CODE_TYPE CodeType,
EFI_STATUS_CODE_VALUE Value,
UINT32 Instance,
EFI_GUID *CallerId,
EFI_STATUS_CODE_DATA *Data
);

struct _EFI_SMM_STATUS_CODE_PROTOCOL {
EFI_SMM_REPORT_STATUS_CODE ReportStatusCode;
};

extern EFI_GUID gEfiSmmStatusCodeProtocolGuid;
typedef struct {
UINTN SwSmiInputValue;
} EFI_SMM_SW_REGISTER_CONTEXT;

typedef struct {

UINTN SwSmiCpuIndex;

UINT8 CommandPort;

UINT8 DataPort;
} EFI_SMM_SW_CONTEXT;

typedef struct _EFI_SMM_SW_DISPATCH2_PROTOCOL EFI_SMM_SW_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_SW_REGISTER2)(
EFI_SMM_SW_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_SW_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_SW_UNREGISTER2)(
EFI_SMM_SW_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);
struct _EFI_SMM_SW_DISPATCH2_PROTOCOL {
EFI_SMM_SW_REGISTER2 Register;
EFI_SMM_SW_UNREGISTER2 UnRegister;

UINTN MaximumSwiValue;
};

extern EFI_GUID gEfiSmmSwDispatch2ProtocolGuid;
typedef enum {
SxS0,
SxS1,
SxS2,
SxS3,
SxS4,
SxS5,
EfiMaximumSleepType
} EFI_SLEEP_TYPE;

typedef enum {
SxEntry,
SxExit,
EfiMaximumPhase
} EFI_SLEEP_PHASE;

typedef struct {
EFI_SLEEP_TYPE Type;
EFI_SLEEP_PHASE Phase;
} EFI_SMM_SX_REGISTER_CONTEXT;

typedef struct _EFI_SMM_SX_DISPATCH2_PROTOCOL EFI_SMM_SX_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_SX_REGISTER2)(
EFI_SMM_SX_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_SX_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_SX_UNREGISTER2)(
EFI_SMM_SX_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_SX_DISPATCH2_PROTOCOL {
EFI_SMM_SX_REGISTER2 Register;
EFI_SMM_SX_UNREGISTER2 UnRegister;
};

extern EFI_GUID gEfiSmmSxDispatch2ProtocolGuid;
typedef enum {
UsbLegacy,
UsbWake
} EFI_USB_SMI_TYPE;

typedef struct {

EFI_USB_SMI_TYPE Type;

EFI_DEVICE_PATH_PROTOCOL *Device;
} EFI_SMM_USB_REGISTER_CONTEXT;

typedef struct _EFI_SMM_USB_DISPATCH2_PROTOCOL EFI_SMM_USB_DISPATCH2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SMM_USB_REGISTER2)(
EFI_SMM_USB_DISPATCH2_PROTOCOL *This,
EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
EFI_SMM_USB_REGISTER_CONTEXT *RegisterContext,
EFI_HANDLE *DispatchHandle
);
typedef
EFI_STATUS
( *EFI_SMM_USB_UNREGISTER2)(
EFI_SMM_USB_DISPATCH2_PROTOCOL *This,
EFI_HANDLE DispatchHandle
);

struct _EFI_SMM_USB_DISPATCH2_PROTOCOL {
EFI_SMM_USB_REGISTER2 Register;
EFI_SMM_USB_UNREGISTER2 UnRegister;
};

extern EFI_GUID gEfiSmmUsbDispatch2ProtocolGuid;
typedef
EFI_STATUS
( *EFI_REPORT_STATUS_CODE)(
EFI_STATUS_CODE_TYPE Type,
EFI_STATUS_CODE_VALUE Value,
UINT32 Instance,
EFI_GUID *CallerId ,
EFI_STATUS_CODE_DATA *Data
);

typedef struct _EFI_STATUS_CODE_PROTOCOL {
EFI_REPORT_STATUS_CODE ReportStatusCode;
} EFI_STATUS_CODE_PROTOCOL;

extern EFI_GUID gEfiStatusCodeRuntimeProtocolGuid;
typedef struct _EFI_STORAGE_SECURITY_COMMAND_PROTOCOL EFI_STORAGE_SECURITY_COMMAND_PROTOCOL;
typedef
EFI_STATUS
( *EFI_STORAGE_SECURITY_RECEIVE_DATA)(
EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *This,
UINT32 MediaId,
UINT64 Timeout,
UINT8 SecurityProtocolId,
UINT16 SecurityProtocolSpecificData,
UINTN PayloadBufferSize,
void *PayloadBuffer,
UINTN *PayloadTransferSize
);
typedef
EFI_STATUS
( *EFI_STORAGE_SECURITY_SEND_DATA) (
EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *This,
UINT32 MediaId,
UINT64 Timeout,
UINT8 SecurityProtocolId,
UINT16 SecurityProtocolSpecificData,
UINTN PayloadBufferSize,
void *PayloadBuffer
);
struct _EFI_STORAGE_SECURITY_COMMAND_PROTOCOL {
EFI_STORAGE_SECURITY_RECEIVE_DATA ReceiveData;
EFI_STORAGE_SECURITY_SEND_DATA SendData;
};

extern EFI_GUID gEfiStorageSecurityCommandProtocolGuid;
typedef union {
ACPI_SMALL_RESOURCE_HEADER *SmallHeader;
ACPI_LARGE_RESOURCE_HEADER *LargeHeader;
} ACPI_RESOURCE_HEADER_PTR;

typedef struct {
UINT8 Register;
UINT8 AndMask;
UINT8 OrMask;
} EFI_SIO_REGISTER_MODIFY;

typedef struct _EFI_SIO_PROTOCOL EFI_SIO_PROTOCOL;
typedef
EFI_STATUS
( *EFI_SIO_REGISTER_ACCESS)(
EFI_SIO_PROTOCOL *This,
BOOLEAN Write,
BOOLEAN ExitCfgMode,
UINT8 Register,
UINT8 *Value
);
typedef
EFI_STATUS
( *EFI_SIO_GET_RESOURCES)(
EFI_SIO_PROTOCOL *This,
ACPI_RESOURCE_HEADER_PTR *ResourceList
);
typedef
EFI_STATUS
( *EFI_SIO_SET_RESOURCES)(
EFI_SIO_PROTOCOL *This,
ACPI_RESOURCE_HEADER_PTR ResourceList
);
typedef
EFI_STATUS
( *EFI_SIO_POSSIBLE_RESOURCES)(
EFI_SIO_PROTOCOL *This,
ACPI_RESOURCE_HEADER_PTR *ResourceCollection
);
typedef
EFI_STATUS
( *EFI_SIO_MODIFY)(
EFI_SIO_PROTOCOL *This,
EFI_SIO_REGISTER_MODIFY *Command,
UINTN NumberOfCommands
);

struct _EFI_SIO_PROTOCOL {
EFI_SIO_REGISTER_ACCESS RegisterAccess;
EFI_SIO_GET_RESOURCES GetResources;
EFI_SIO_SET_RESOURCES SetResources;
EFI_SIO_POSSIBLE_RESOURCES PossibleResources;
EFI_SIO_MODIFY Modify;
};

extern EFI_GUID gEfiSioProtocolGuid;
typedef struct _EFI_TAPE_IO_PROTOCOL EFI_TAPE_IO_PROTOCOL;

typedef struct _EFI_TAPE_HEADER {
UINT64 Signature;
UINT32 Revision;
UINT32 BootDescSize;
UINT32 BootDescCRC;
EFI_GUID TapeGUID;
EFI_GUID TapeType;
EFI_GUID TapeUnique;
UINT32 BLLocation;
UINT32 BLBlocksize;
UINT32 BLFilesize;
CHAR8 OSVersion[40];
CHAR8 AppVersion[40];
CHAR8 CreationDate[10];
CHAR8 CreationTime[10];
CHAR8 SystemName[256];
CHAR8 TapeTitle[120];
CHAR8 pad[468];
} EFI_TAPE_HEADER;
typedef
EFI_STATUS
( *EFI_TAPE_READ)(
EFI_TAPE_IO_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_TAPE_WRITE)(
EFI_TAPE_IO_PROTOCOL *This,
UINTN *BufferSize,
void *Buffer
);
typedef
EFI_STATUS
( *EFI_TAPE_REWIND)(
EFI_TAPE_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_TAPE_SPACE)(
EFI_TAPE_IO_PROTOCOL *This,
INTN Direction,
UINTN Type
);
typedef
EFI_STATUS
( *EFI_TAPE_WRITEFM)(
EFI_TAPE_IO_PROTOCOL *This,
UINTN Count
);
typedef
EFI_STATUS
( *EFI_TAPE_RESET)(
EFI_TAPE_IO_PROTOCOL *This,
BOOLEAN ExtendedVerification
);

struct _EFI_TAPE_IO_PROTOCOL {
EFI_TAPE_READ TapeRead;
EFI_TAPE_WRITE TapeWrite;
EFI_TAPE_REWIND TapeRewind;
EFI_TAPE_SPACE TapeSpace;
EFI_TAPE_WRITEFM TapeWriteFM;
EFI_TAPE_RESET TapeReset;
};

extern EFI_GUID gEfiTapeIoProtocolGuid;
#pragma pack (1)

typedef UINT8 TPM_AUTH_DATA_USAGE;

typedef UINT8 TPM_PAYLOAD_TYPE;

typedef UINT8 TPM_VERSION_BYTE;

typedef UINT8 TPM_DA_STATE;

typedef UINT16 TPM_TAG;

typedef UINT16 TPM_PROTOCOL_ID;

typedef UINT16 TPM_STARTUP_TYPE;

typedef UINT16 TPM_ENC_SCHEME;

typedef UINT16 TPM_SIG_SCHEME;

typedef UINT16 TPM_MIGRATE_SCHEME;

typedef UINT16 TPM_PHYSICAL_PRESENCE;

typedef UINT16 TPM_ENTITY_TYPE;

typedef UINT16 TPM_KEY_USAGE;

typedef UINT16 TPM_EK_TYPE;

typedef UINT16 TPM_STRUCTURE_TAG;

typedef UINT16 TPM_PLATFORM_SPECIFIC;

typedef UINT32 TPM_COMMAND_CODE;

typedef UINT32 TPM_CAPABILITY_AREA;

typedef UINT32 TPM_KEY_FLAGS;

typedef UINT32 TPM_ALGORITHM_ID;

typedef UINT32 TPM_MODIFIER_INDICATOR;

typedef UINT32 TPM_ACTUAL_COUNT;

typedef UINT32 TPM_TRANSPORT_ATTRIBUTES;

typedef UINT32 TPM_AUTHHANDLE;

typedef UINT32 TPM_DIRINDEX;

typedef UINT32 TPM_KEY_HANDLE;

typedef UINT32 TPM_PCRINDEX;

typedef UINT32 TPM_RESULT;

typedef UINT32 TPM_RESOURCE_TYPE;

typedef UINT32 TPM_KEY_CONTROL;

typedef UINT32 TPM_NV_INDEX;

typedef UINT32 TPM_FAMILY_ID;

typedef UINT32 TPM_FAMILY_VERIFICATION;

typedef UINT32 TPM_STARTUP_EFFECTS;

typedef UINT32 TPM_SYM_MODE;

typedef UINT32 TPM_FAMILY_FLAGS;

typedef UINT32 TPM_DELEGATE_INDEX;

typedef UINT32 TPM_CMK_DELEGATE;

typedef UINT32 TPM_COUNT_ID;

typedef UINT32 TPM_REDIT_COMMAND;

typedef UINT32 TPM_TRANSHANDLE;

typedef UINT32 TPM_HANDLE;

typedef UINT32 TPM_FAMILY_OPERATION;
typedef struct tdTPM_STRUCT_VER {
UINT8 major;
UINT8 minor;
UINT8 revMajor;
UINT8 revMinor;
} TPM_STRUCT_VER;

typedef struct tdTPM_VERSION {
TPM_VERSION_BYTE major;
TPM_VERSION_BYTE minor;
UINT8 revMajor;
UINT8 revMinor;
} TPM_VERSION;
typedef struct tdTPM_DIGEST{
UINT8 digest[0x14];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_CHOSENID_HASH;

typedef TPM_DIGEST TPM_COMPOSITE_HASH;

typedef TPM_DIGEST TPM_DIRVALUE;

typedef TPM_DIGEST TPM_HMAC;

typedef TPM_DIGEST TPM_PCRVALUE;

typedef TPM_DIGEST TPM_AUDITDIGEST;

typedef struct tdTPM_NONCE{
UINT8 nonce[20];
} TPM_NONCE;

typedef TPM_NONCE TPM_DAA_TPM_SEED;

typedef TPM_NONCE TPM_DAA_CONTEXT_SEED;
typedef UINT8 tdTPM_AUTHDATA[20];

typedef tdTPM_AUTHDATA TPM_AUTHDATA;

typedef TPM_AUTHDATA TPM_SECRET;

typedef TPM_AUTHDATA TPM_ENCAUTH;

typedef struct tdTPM_KEY_HANDLE_LIST {
UINT16 loaded;
TPM_KEY_HANDLE handle[1];
} TPM_KEY_HANDLE_LIST;
typedef enum tdTPM_KEY_FLAGS {
redirection = 0x00000001,
migratable = 0x00000002,
isVolatile = 0x00000004,
pcrIgnoredOnRead = 0x00000008,
migrateAuthority = 0x00000010
} TPM_KEY_FLAGS_BITS;

typedef struct tdTPM_CHANGEAUTH_VALIDATE {
TPM_SECRET newAuthSecret;
TPM_NONCE n1;
} TPM_CHANGEAUTH_VALIDATE;
typedef struct tdTPM_KEY_PARMS {
TPM_ALGORITHM_ID algorithmID;
TPM_ENC_SCHEME encScheme;
TPM_SIG_SCHEME sigScheme;
UINT32 parmSize;
UINT8 *parms;
} TPM_KEY_PARMS;

typedef struct tdTPM_STORE_PUBKEY {
UINT32 keyLength;
UINT8 key[1];
} TPM_STORE_PUBKEY;

typedef struct tdTPM_PUBKEY{
TPM_KEY_PARMS algorithmParms;
TPM_STORE_PUBKEY pubKey;
} TPM_PUBKEY;

typedef struct tdTPM_MIGRATIONKEYAUTH{
TPM_PUBKEY migrationKey;
TPM_MIGRATE_SCHEME migrationScheme;
TPM_DIGEST digest;
} TPM_MIGRATIONKEYAUTH;

typedef struct tdTPM_COUNTER_VALUE{
TPM_STRUCTURE_TAG tag;
UINT8 label[4];
TPM_ACTUAL_COUNT counter;
} TPM_COUNTER_VALUE;

typedef struct tdTPM_SIGN_INFO {
TPM_STRUCTURE_TAG tag;
UINT8 fixed[4];
TPM_NONCE replay;
UINT32 dataLen;
UINT8 *data;
} TPM_SIGN_INFO;

typedef struct tdTPM_MSA_COMPOSITE {
UINT32 MSAlist;
TPM_DIGEST migAuthDigest[1];
} TPM_MSA_COMPOSITE;

typedef struct tdTPM_CMK_AUTH{
TPM_DIGEST migrationAuthorityDigest;
TPM_DIGEST destinationKeyDigest;
TPM_DIGEST sourceKeyDigest;
} TPM_CMK_AUTH;
typedef struct tdTPM_SELECT_SIZE {
UINT8 major;
UINT8 minor;
UINT16 reqSize;
} TPM_SELECT_SIZE;

typedef struct tdTPM_CMK_MIGAUTH{
TPM_STRUCTURE_TAG tag;
TPM_DIGEST msaDigest;
TPM_DIGEST pubKeyDigest;
} TPM_CMK_MIGAUTH;

typedef struct tdTPM_CMK_SIGTICKET{
TPM_STRUCTURE_TAG tag;
TPM_DIGEST verKeyDigest;
TPM_DIGEST signedData;
} TPM_CMK_SIGTICKET;

typedef struct tdTPM_CMK_MA_APPROVAL{
TPM_STRUCTURE_TAG tag;
TPM_DIGEST migrationAuthorityDigest;
} TPM_CMK_MA_APPROVAL;
typedef struct tdTPM_PERMANENT_FLAGS{
TPM_STRUCTURE_TAG tag;
BOOLEAN disable;
BOOLEAN ownership;
BOOLEAN deactivated;
BOOLEAN readPubek;
BOOLEAN disableOwnerClear;
BOOLEAN allowMaintenance;
BOOLEAN physicalPresenceLifetimeLock;
BOOLEAN physicalPresenceHWEnable;
BOOLEAN physicalPresenceCMDEnable;
BOOLEAN CEKPUsed;
BOOLEAN TPMpost;
BOOLEAN TPMpostLock;
BOOLEAN FIPS;
BOOLEAN operator;
BOOLEAN enableRevokeEK;
BOOLEAN nvLocked;
BOOLEAN readSRKPub;
BOOLEAN tpmEstablished;
BOOLEAN maintenanceDone;
BOOLEAN disableFullDALogicInfo;
} TPM_PERMANENT_FLAGS;
typedef struct tdTPM_STCLEAR_FLAGS{
TPM_STRUCTURE_TAG tag;
BOOLEAN deactivated;
BOOLEAN disableForceClear;
BOOLEAN physicalPresence;
BOOLEAN physicalPresenceLock;
BOOLEAN bGlobalLock;
} TPM_STCLEAR_FLAGS;
typedef struct tdTPM_STANY_FLAGS{
TPM_STRUCTURE_TAG tag;
BOOLEAN postInitialise;
TPM_MODIFIER_INDICATOR localityModifier;
BOOLEAN transportExclusive;
BOOLEAN TOSPresent;
} TPM_STANY_FLAGS;
typedef struct tdTPM_STCLEAR_DATA{
TPM_STRUCTURE_TAG tag;
TPM_NONCE contextNonceKey;
TPM_COUNT_ID countID;
UINT32 ownerReference;
BOOLEAN disableResetLock;
TPM_PCRVALUE PCR[16];
UINT32 deferredPhysicalPresence;
}TPM_STCLEAR_DATA;
typedef struct tdTPM_PCR_SELECTION {
UINT16 sizeOfSelect;
UINT8 pcrSelect[1];
} TPM_PCR_SELECTION;

typedef struct tdTPM_PCR_COMPOSITE {
TPM_PCR_SELECTION select;
UINT32 valueSize;
TPM_PCRVALUE pcrValue[1];
} TPM_PCR_COMPOSITE;

typedef struct tdTPM_PCR_INFO {
TPM_PCR_SELECTION pcrSelection;
TPM_COMPOSITE_HASH digestAtRelease;
TPM_COMPOSITE_HASH digestAtCreation;
} TPM_PCR_INFO;

typedef UINT8 TPM_LOCALITY_SELECTION;
typedef struct tdTPM_PCR_INFO_LONG {
TPM_STRUCTURE_TAG tag;
TPM_LOCALITY_SELECTION localityAtCreation;
TPM_LOCALITY_SELECTION localityAtRelease;
TPM_PCR_SELECTION creationPCRSelection;
TPM_PCR_SELECTION releasePCRSelection;
TPM_COMPOSITE_HASH digestAtCreation;
TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO_LONG;

typedef struct tdTPM_PCR_INFO_SHORT{
TPM_PCR_SELECTION pcrSelection;
TPM_LOCALITY_SELECTION localityAtRelease;
TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO_SHORT;

typedef struct tdTPM_PCR_ATTRIBUTES{
BOOLEAN pcrReset;
TPM_LOCALITY_SELECTION pcrExtendLocal;
TPM_LOCALITY_SELECTION pcrResetLocal;
} TPM_PCR_ATTRIBUTES;
typedef struct tdTPM_STORED_DATA {
TPM_STRUCT_VER ver;
UINT32 sealInfoSize;
UINT8 *sealInfo;
UINT32 encDataSize;
UINT8 *encData;
} TPM_STORED_DATA;

typedef struct tdTPM_STORED_DATA12 {
TPM_STRUCTURE_TAG tag;
TPM_ENTITY_TYPE et;
UINT32 sealInfoSize;
UINT8 *sealInfo;
UINT32 encDataSize;
UINT8 *encData;
} TPM_STORED_DATA12;

typedef struct tdTPM_SEALED_DATA {
TPM_PAYLOAD_TYPE payload;
TPM_SECRET authData;
TPM_NONCE tpmProof;
TPM_DIGEST storedDigest;
UINT32 dataSize;
UINT8 *data;
} TPM_SEALED_DATA;

typedef struct tdTPM_SYMMETRIC_KEY {
TPM_ALGORITHM_ID algId;
TPM_ENC_SCHEME encScheme;
UINT16 dataSize;
UINT8 *data;
} TPM_SYMMETRIC_KEY;

typedef struct tdTPM_BOUND_DATA {
TPM_STRUCT_VER ver;
TPM_PAYLOAD_TYPE payload;
UINT8 payloadData[1];
} TPM_BOUND_DATA;
typedef struct tdTPM_KEY{
TPM_STRUCT_VER ver;
TPM_KEY_USAGE keyUsage;
TPM_KEY_FLAGS keyFlags;
TPM_AUTH_DATA_USAGE authDataUsage;
TPM_KEY_PARMS algorithmParms;
UINT32 PCRInfoSize;
UINT8 *PCRInfo;
TPM_STORE_PUBKEY pubKey;
UINT32 encDataSize;
UINT8 *encData;
} TPM_KEY;

typedef struct tdTPM_KEY12{
TPM_STRUCTURE_TAG tag;
UINT16 fill;
TPM_KEY_USAGE keyUsage;
TPM_KEY_FLAGS keyFlags;
TPM_AUTH_DATA_USAGE authDataUsage;
TPM_KEY_PARMS algorithmParms;
UINT32 PCRInfoSize;
UINT8 *PCRInfo;
TPM_STORE_PUBKEY pubKey;
UINT32 encDataSize;
UINT8 *encData;
} TPM_KEY12;

typedef struct tdTPM_STORE_PRIVKEY {
UINT32 keyLength;
UINT8 *key;
} TPM_STORE_PRIVKEY;

typedef struct tdTPM_STORE_ASYMKEY {
TPM_PAYLOAD_TYPE payload;
TPM_SECRET usageAuth;
TPM_SECRET migrationAuth;
TPM_DIGEST pubDataDigest;
TPM_STORE_PRIVKEY privKey;
} TPM_STORE_ASYMKEY;

typedef struct tdTPM_MIGRATE_ASYMKEY {
TPM_PAYLOAD_TYPE payload;
TPM_SECRET usageAuth;
TPM_DIGEST pubDataDigest;
UINT32 partPrivKeyLen;
UINT8 *partPrivKey;
} TPM_MIGRATE_ASYMKEY;
typedef struct tdTPM_CERTIFY_INFO {
TPM_STRUCT_VER version;
TPM_KEY_USAGE keyUsage;
TPM_KEY_FLAGS keyFlags;
TPM_AUTH_DATA_USAGE authDataUsage;
TPM_KEY_PARMS algorithmParms;
TPM_DIGEST pubkeyDigest;
TPM_NONCE data;
BOOLEAN parentPCRStatus;
UINT32 PCRInfoSize;
UINT8 *PCRInfo;
} TPM_CERTIFY_INFO;

typedef struct tdTPM_CERTIFY_INFO2 {
TPM_STRUCTURE_TAG tag;
UINT8 fill;
TPM_PAYLOAD_TYPE payloadType;
TPM_KEY_USAGE keyUsage;
TPM_KEY_FLAGS keyFlags;
TPM_AUTH_DATA_USAGE authDataUsage;
TPM_KEY_PARMS algorithmParms;
TPM_DIGEST pubkeyDigest;
TPM_NONCE data;
BOOLEAN parentPCRStatus;
UINT32 PCRInfoSize;
UINT8 *PCRInfo;
UINT32 migrationAuthoritySize;
UINT8 *migrationAuthority;
} TPM_CERTIFY_INFO2;

typedef struct tdTPM_QUOTE_INFO {
TPM_STRUCT_VER version;
UINT8 fixed[4];
TPM_COMPOSITE_HASH digestValue;
TPM_NONCE externalData;
} TPM_QUOTE_INFO;

typedef struct tdTPM_QUOTE_INFO2 {
TPM_STRUCTURE_TAG tag;
UINT8 fixed[4];
TPM_NONCE externalData;
TPM_PCR_INFO_SHORT infoShort;
} TPM_QUOTE_INFO2;
typedef struct tdTPM_EK_BLOB {
TPM_STRUCTURE_TAG tag;
TPM_EK_TYPE ekType;
UINT32 blobSize;
UINT8 *blob;
} TPM_EK_BLOB;

typedef struct tdTPM_EK_BLOB_ACTIVATE {
TPM_STRUCTURE_TAG tag;
TPM_SYMMETRIC_KEY sessionKey;
TPM_DIGEST idDigest;
TPM_PCR_INFO_SHORT pcrInfo;
} TPM_EK_BLOB_ACTIVATE;

typedef struct tdTPM_EK_BLOB_AUTH {
TPM_STRUCTURE_TAG tag;
TPM_SECRET authValue;
} TPM_EK_BLOB_AUTH;

typedef struct tdTPM_IDENTITY_CONTENTS {
TPM_STRUCT_VER ver;
UINT32 ordinal;
TPM_CHOSENID_HASH labelPrivCADigest;
TPM_PUBKEY identityPubKey;
} TPM_IDENTITY_CONTENTS;

typedef struct tdTPM_IDENTITY_REQ {
UINT32 asymSize;
UINT32 symSize;
TPM_KEY_PARMS asymAlgorithm;
TPM_KEY_PARMS symAlgorithm;
UINT8 *asymBlob;
UINT8 *symBlob;
} TPM_IDENTITY_REQ;

typedef struct tdTPM_IDENTITY_PROOF {
TPM_STRUCT_VER ver;
UINT32 labelSize;
UINT32 identityBindingSize;
UINT32 endorsementSize;
UINT32 platformSize;
UINT32 conformanceSize;
TPM_PUBKEY identityKey;
UINT8 *labelArea;
UINT8 *identityBinding;
UINT8 *endorsementCredential;
UINT8 *platformCredential;
UINT8 *conformanceCredential;
} TPM_IDENTITY_PROOF;

typedef struct tdTPM_ASYM_CA_CONTENTS {
TPM_SYMMETRIC_KEY sessionKey;
TPM_DIGEST idDigest;
} TPM_ASYM_CA_CONTENTS;

typedef struct tdTPM_SYM_CA_ATTESTATION {
UINT32 credSize;
TPM_KEY_PARMS algorithm;
UINT8 *credential;
} TPM_SYM_CA_ATTESTATION;

typedef struct tdTPM_CURRENT_TICKS {
TPM_STRUCTURE_TAG tag;
UINT64 currentTicks;
UINT16 tickRate;
TPM_NONCE tickNonce;
} TPM_CURRENT_TICKS;
typedef struct tdTPM_TRANSPORT_PUBLIC {
TPM_STRUCTURE_TAG tag;
TPM_TRANSPORT_ATTRIBUTES transAttributes;
TPM_ALGORITHM_ID algId;
TPM_ENC_SCHEME encScheme;
} TPM_TRANSPORT_PUBLIC;
typedef struct tdTPM_TRANSPORT_INTERNAL {
TPM_STRUCTURE_TAG tag;
TPM_AUTHDATA authData;
TPM_TRANSPORT_PUBLIC transPublic;
TPM_TRANSHANDLE transHandle;
TPM_NONCE transNonceEven;
TPM_DIGEST transDigest;
} TPM_TRANSPORT_INTERNAL;

typedef struct tdTPM_TRANSPORT_LOG_IN {
TPM_STRUCTURE_TAG tag;
TPM_DIGEST parameters;
TPM_DIGEST pubKeyHash;
} TPM_TRANSPORT_LOG_IN;

typedef struct tdTPM_TRANSPORT_LOG_OUT {
TPM_STRUCTURE_TAG tag;
TPM_CURRENT_TICKS currentTicks;
TPM_DIGEST parameters;
TPM_MODIFIER_INDICATOR locality;
} TPM_TRANSPORT_LOG_OUT;

typedef struct tdTPM_TRANSPORT_AUTH {
TPM_STRUCTURE_TAG tag;
TPM_AUTHDATA authData;
} TPM_TRANSPORT_AUTH;
typedef struct tdTPM_AUDIT_EVENT_IN {
TPM_STRUCTURE_TAG tag;
TPM_DIGEST inputParms;
TPM_COUNTER_VALUE auditCount;
} TPM_AUDIT_EVENT_IN;

typedef struct tdTPM_AUDIT_EVENT_OUT {
TPM_STRUCTURE_TAG tag;
TPM_COMMAND_CODE ordinal;
TPM_DIGEST outputParms;
TPM_COUNTER_VALUE auditCount;
TPM_RESULT returnCode;
} TPM_AUDIT_EVENT_OUT;
typedef struct tdTPM_CONTEXT_BLOB {
TPM_STRUCTURE_TAG tag;
TPM_RESOURCE_TYPE resourceType;
TPM_HANDLE handle;
UINT8 label[16];
UINT32 contextCount;
TPM_DIGEST integrityDigest;
UINT32 additionalSize;
UINT8 *additionalData;
UINT32 sensitiveSize;
UINT8 *sensitiveData;
} TPM_CONTEXT_BLOB;

typedef struct tdTPM_CONTEXT_SENSITIVE {
TPM_STRUCTURE_TAG tag;
TPM_NONCE contextNonce;
UINT32 internalSize;
UINT8 *internalData;
} TPM_CONTEXT_SENSITIVE;
typedef struct tdTPM_NV_ATTRIBUTES {
TPM_STRUCTURE_TAG tag;
UINT32 attributes;
} TPM_NV_ATTRIBUTES;
typedef struct tdTPM_NV_DATA_PUBLIC {
TPM_STRUCTURE_TAG tag;
TPM_NV_INDEX nvIndex;
TPM_PCR_INFO_SHORT pcrInfoRead;
TPM_PCR_INFO_SHORT pcrInfoWrite;
TPM_NV_ATTRIBUTES permission;
BOOLEAN bReadSTClear;
BOOLEAN bWriteSTClear;
BOOLEAN bWriteDefine;
UINT32 dataSize;
} TPM_NV_DATA_PUBLIC;
typedef struct tdTPM_DELEGATIONS {
TPM_STRUCTURE_TAG tag;
UINT32 delegateType;
UINT32 per1;
UINT32 per2;
} TPM_DELEGATIONS;
typedef struct tdTPM_FAMILY_LABEL {
UINT8 label;
} TPM_FAMILY_LABEL;

typedef struct tdTPM_FAMILY_TABLE_ENTRY {
TPM_STRUCTURE_TAG tag;
TPM_FAMILY_LABEL label;
TPM_FAMILY_ID familyID;
TPM_FAMILY_VERIFICATION verificationCount;
TPM_FAMILY_FLAGS flags;
} TPM_FAMILY_TABLE_ENTRY;

typedef struct tdTPM_FAMILY_TABLE{
TPM_FAMILY_TABLE_ENTRY famTableRow[8];
} TPM_FAMILY_TABLE;

typedef struct tdTPM_DELEGATE_LABEL {
UINT8 label;
} TPM_DELEGATE_LABEL;

typedef struct tdTPM_DELEGATE_PUBLIC {
TPM_STRUCTURE_TAG tag;
TPM_DELEGATE_LABEL label;
TPM_PCR_INFO_SHORT pcrInfo;
TPM_DELEGATIONS permissions;
TPM_FAMILY_ID familyID;
TPM_FAMILY_VERIFICATION verificationCount;
} TPM_DELEGATE_PUBLIC;

typedef struct tdTPM_DELEGATE_TABLE_ROW {
TPM_STRUCTURE_TAG tag;
TPM_DELEGATE_PUBLIC pub;
TPM_SECRET authValue;
} TPM_DELEGATE_TABLE_ROW;

typedef struct tdTPM_DELEGATE_TABLE{
TPM_DELEGATE_TABLE_ROW delRow[2];
} TPM_DELEGATE_TABLE;

typedef struct tdTPM_DELEGATE_SENSITIVE {
TPM_STRUCTURE_TAG tag;
TPM_SECRET authValue;
} TPM_DELEGATE_SENSITIVE;

typedef struct tdTPM_DELEGATE_OWNER_BLOB {
TPM_STRUCTURE_TAG tag;
TPM_DELEGATE_PUBLIC pub;
TPM_DIGEST integrityDigest;
UINT32 additionalSize;
UINT8 *additionalArea;
UINT32 sensitiveSize;
UINT8 *sensitiveArea;
} TPM_DELEGATE_OWNER_BLOB;

typedef struct tdTPM_DELEGATE_KEY_BLOB {
TPM_STRUCTURE_TAG tag;
TPM_DELEGATE_PUBLIC pub;
TPM_DIGEST integrityDigest;
TPM_DIGEST pubKeyDigest;
UINT32 additionalSize;
UINT8 *additionalArea;
UINT32 sensitiveSize;
UINT8 *sensitiveArea;
} TPM_DELEGATE_KEY_BLOB;
typedef struct tdTPM_CAP_VERSION_INFO {
TPM_STRUCTURE_TAG tag;
TPM_VERSION version;
UINT16 specLevel;
UINT8 errataRev;
UINT8 tpmVendorID[4];
UINT16 vendorSpecificSize;
UINT8 *vendorSpecific;
} TPM_CAP_VERSION_INFO;

typedef struct tdTPM_DA_ACTION_TYPE {
TPM_STRUCTURE_TAG tag;
UINT32 actions;
} TPM_DA_ACTION_TYPE;
typedef struct tdTPM_DA_INFO {
TPM_STRUCTURE_TAG tag;
TPM_DA_STATE state;
UINT16 currentCount;
UINT16 thresholdCount;
TPM_DA_ACTION_TYPE actionAtThreshold;
UINT32 actionDependValue;
UINT32 vendorDataSize;
UINT8 *vendorData;
} TPM_DA_INFO;

typedef struct tdTPM_DA_INFO_LIMITED {
TPM_STRUCTURE_TAG tag;
TPM_DA_STATE state;
TPM_DA_ACTION_TYPE actionAtThreshold;
UINT32 vendorDataSize;
UINT8 *vendorData;
} TPM_DA_INFO_LIMITED;
typedef struct tdTPM_DAA_ISSUER {
TPM_STRUCTURE_TAG tag;
TPM_DIGEST DAA_digest_R0;
TPM_DIGEST DAA_digest_R1;
TPM_DIGEST DAA_digest_S0;
TPM_DIGEST DAA_digest_S1;
TPM_DIGEST DAA_digest_n;
TPM_DIGEST DAA_digest_gamma;
UINT8 DAA_generic_q[26];
} TPM_DAA_ISSUER;

typedef struct tdTPM_DAA_TPM {
TPM_STRUCTURE_TAG tag;
TPM_DIGEST DAA_digestIssuer;
TPM_DIGEST DAA_digest_v0;
TPM_DIGEST DAA_digest_v1;
TPM_DIGEST DAA_rekey;
UINT32 DAA_count;
} TPM_DAA_TPM;

typedef struct tdTPM_DAA_CONTEXT {
TPM_STRUCTURE_TAG tag;
TPM_DIGEST DAA_digestContext;
TPM_DIGEST DAA_digest;
TPM_DAA_CONTEXT_SEED DAA_contextSeed;
UINT8 DAA_scratch[256];
UINT8 DAA_stage;
} TPM_DAA_CONTEXT;

typedef struct tdTPM_DAA_JOINDATA {
UINT8 DAA_join_u0[128];
UINT8 DAA_join_u1[138];
TPM_DIGEST DAA_digest_n0;
} TPM_DAA_JOINDATA;

typedef struct tdTPM_DAA_BLOB {
TPM_STRUCTURE_TAG tag;
TPM_RESOURCE_TYPE resourceType;
UINT8 label[16];
TPM_DIGEST blobIntegrity;
UINT32 additionalSize;
UINT8 *additionalData;
UINT32 sensitiveSize;
UINT8 *sensitiveData;
} TPM_DAA_BLOB;

typedef struct tdTPM_DAA_SENSITIVE {
TPM_STRUCTURE_TAG tag;
UINT32 internalSize;
UINT8 *internalData;
} TPM_DAA_SENSITIVE;
typedef struct tdTPM_RQU_COMMAND_HDR {
TPM_STRUCTURE_TAG tag;
UINT32 paramSize;
TPM_COMMAND_CODE ordinal;
} TPM_RQU_COMMAND_HDR;

typedef struct tdTPM_RSP_COMMAND_HDR {
TPM_STRUCTURE_TAG tag;
UINT32 paramSize;
TPM_RESULT returnCode;
} TPM_RSP_COMMAND_HDR;

#pragma pack ()
#pragma pack (1)

typedef UINT32 TCG_EVENTTYPE;
typedef TPM_PCRINDEX TCG_PCRINDEX;
typedef TPM_DIGEST TCG_DIGEST;

typedef struct tdTCG_PCR_EVENT {
TCG_PCRINDEX PCRIndex;
TCG_EVENTTYPE EventType;
TCG_DIGEST Digest;
UINT32 EventSize;
UINT8 Event[1];
} TCG_PCR_EVENT;

typedef struct tdTCG_PCR_EVENT_HDR {
TCG_PCRINDEX PCRIndex;
TCG_EVENTTYPE EventType;
TCG_DIGEST Digest;
UINT32 EventSize;
} TCG_PCR_EVENT_HDR;

typedef struct tdEFI_PLATFORM_FIRMWARE_BLOB {
EFI_PHYSICAL_ADDRESS BlobBase;
UINT64 BlobLength;
} EFI_PLATFORM_FIRMWARE_BLOB;

typedef struct tdEFI_IMAGE_LOAD_EVENT {
EFI_PHYSICAL_ADDRESS ImageLocationInMemory;
UINTN ImageLengthInMemory;
UINTN ImageLinkTimeAddress;
UINTN LengthOfDevicePath;
EFI_DEVICE_PATH_PROTOCOL DevicePath[1];
} EFI_IMAGE_LOAD_EVENT;

typedef struct tdEFI_HANDOFF_TABLE_POINTERS {
UINTN NumberOfTables;
EFI_CONFIGURATION_TABLE TableEntry[1];
} EFI_HANDOFF_TABLE_POINTERS;
typedef struct tdEFI_VARIABLE_DATA {
EFI_GUID VariableName;
UINTN UnicodeNameLength;
UINTN VariableDataLength;
CHAR16 UnicodeName[1];
INT8 VariableData[1];
} EFI_VARIABLE_DATA;

typedef struct tdEFI_GPT_DATA {
EFI_PARTITION_TABLE_HEADER EfiPartitionHeader;
UINTN NumberOfPartitions;
EFI_PARTITION_ENTRY Partitions[1];
} EFI_GPT_DATA;

#pragma pack ()

typedef struct _EFI_TCG_PROTOCOL EFI_TCG_PROTOCOL;

typedef struct {
UINT8 Major;
UINT8 Minor;
UINT8 RevMajor;
UINT8 RevMinor;
} TCG_VERSION;

typedef struct _TCG_EFI_BOOT_SERVICE_CAPABILITY {
UINT8 Size;
TCG_VERSION StructureVersion;
TCG_VERSION ProtocolSpecVersion;
UINT8 HashAlgorithmBitmap;

BOOLEAN TPMPresentFlag;
BOOLEAN TPMDeactivatedFlag;
} TCG_EFI_BOOT_SERVICE_CAPABILITY;

typedef UINT32 TCG_ALGORITHM_ID;
typedef
EFI_STATUS
( *EFI_TCG_STATUS_CHECK)(
EFI_TCG_PROTOCOL *This,
TCG_EFI_BOOT_SERVICE_CAPABILITY
*ProtocolCapability,
UINT32 *TCGFeatureFlags,
EFI_PHYSICAL_ADDRESS *EventLogLocation,
EFI_PHYSICAL_ADDRESS *EventLogLastEntry
);
typedef
EFI_STATUS
( *EFI_TCG_HASH_ALL)(
EFI_TCG_PROTOCOL *This,
UINT8 *HashData,
UINT64 HashDataLen,
TCG_ALGORITHM_ID AlgorithmId,
UINT64 *HashedDataLen,
UINT8 **HashedDataResult
);
typedef
EFI_STATUS
( *EFI_TCG_LOG_EVENT)(
EFI_TCG_PROTOCOL *This,
TCG_PCR_EVENT *TCGLogData,
UINT32 *EventNumber,
UINT32 Flags
);
typedef
EFI_STATUS
( *EFI_TCG_PASS_THROUGH_TO_TPM)(
EFI_TCG_PROTOCOL *This,
UINT32 TpmInputParameterBlockSize,
UINT8 *TpmInputParameterBlock,
UINT32 TpmOutputParameterBlockSize,
UINT8 *TpmOutputParameterBlock
);
typedef
EFI_STATUS
( *EFI_TCG_HASH_LOG_EXTEND_EVENT)(
EFI_TCG_PROTOCOL *This,
EFI_PHYSICAL_ADDRESS HashData,
UINT64 HashDataLen,
TCG_ALGORITHM_ID AlgorithmId,
TCG_PCR_EVENT *TCGLogData,
UINT32 *EventNumber,
EFI_PHYSICAL_ADDRESS *EventLogLastEntry
);

struct _EFI_TCG_PROTOCOL {
EFI_TCG_STATUS_CHECK StatusCheck;
EFI_TCG_HASH_ALL HashAll;
EFI_TCG_LOG_EVENT LogEvent;
EFI_TCG_PASS_THROUGH_TO_TPM PassThroughToTpm;
EFI_TCG_HASH_LOG_EXTEND_EVENT HashLogExtendEvent;
};

extern EFI_GUID gEfiTcgProtocolGuid;
typedef struct _EFI_TCP4_PROTOCOL EFI_TCP4_PROTOCOL;

typedef struct {
EFI_HANDLE InstanceHandle;
EFI_IPv4_ADDRESS LocalAddress;
UINT16 LocalPort;
EFI_IPv4_ADDRESS RemoteAddress;
UINT16 RemotePort;
} EFI_TCP4_SERVICE_POINT;

typedef struct {
EFI_HANDLE DriverHandle;
UINT32 ServiceCount;
EFI_TCP4_SERVICE_POINT Services[1];
} EFI_TCP4_VARIABLE_DATA;

typedef struct {
BOOLEAN UseDefaultAddress;
EFI_IPv4_ADDRESS StationAddress;
EFI_IPv4_ADDRESS SubnetMask;
UINT16 StationPort;
EFI_IPv4_ADDRESS RemoteAddress;
UINT16 RemotePort;
BOOLEAN ActiveFlag;
} EFI_TCP4_ACCESS_POINT;

typedef struct {
UINT32 ReceiveBufferSize;
UINT32 SendBufferSize;
UINT32 MaxSynBackLog;
UINT32 ConnectionTimeout;
UINT32 DataRetries;
UINT32 FinTimeout;
UINT32 TimeWaitTimeout;
UINT32 KeepAliveProbes;
UINT32 KeepAliveTime;
UINT32 KeepAliveInterval;
BOOLEAN EnableNagle;
BOOLEAN EnableTimeStamp;
BOOLEAN EnableWindowScaling;
BOOLEAN EnableSelectiveAck;
BOOLEAN EnablePathMtuDiscovery;
} EFI_TCP4_OPTION;

typedef struct {

UINT8 TypeOfService;
UINT8 TimeToLive;

EFI_TCP4_ACCESS_POINT AccessPoint;

EFI_TCP4_OPTION *ControlOption;
} EFI_TCP4_CONFIG_DATA;

typedef enum {
Tcp4StateClosed = 0,
Tcp4StateListen = 1,
Tcp4StateSynSent = 2,
Tcp4StateSynReceived = 3,
Tcp4StateEstablished = 4,
Tcp4StateFinWait1 = 5,
Tcp4StateFinWait2 = 6,
Tcp4StateClosing = 7,
Tcp4StateTimeWait = 8,
Tcp4StateCloseWait = 9,
Tcp4StateLastAck = 10
} EFI_TCP4_CONNECTION_STATE;

typedef struct {
EFI_EVENT Event;
EFI_STATUS Status;
} EFI_TCP4_COMPLETION_TOKEN;

typedef struct {
EFI_TCP4_COMPLETION_TOKEN CompletionToken;
} EFI_TCP4_CONNECTION_TOKEN;

typedef struct {
EFI_TCP4_COMPLETION_TOKEN CompletionToken;
EFI_HANDLE NewChildHandle;
} EFI_TCP4_LISTEN_TOKEN;

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_TCP4_FRAGMENT_DATA;

typedef struct {
BOOLEAN UrgentFlag;
UINT32 DataLength;
UINT32 FragmentCount;
EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_RECEIVE_DATA;

typedef struct {
BOOLEAN Push;
BOOLEAN Urgent;
UINT32 DataLength;
UINT32 FragmentCount;
EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_TRANSMIT_DATA;

typedef struct {
EFI_TCP4_COMPLETION_TOKEN CompletionToken;
union {

EFI_TCP4_RECEIVE_DATA *RxData;

EFI_TCP4_TRANSMIT_DATA *TxData;
} Packet;
} EFI_TCP4_IO_TOKEN;

typedef struct {
EFI_TCP4_COMPLETION_TOKEN CompletionToken;
BOOLEAN AbortOnClose;
} EFI_TCP4_CLOSE_TOKEN;
typedef
EFI_STATUS
( *EFI_TCP4_GET_MODE_DATA)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_CONNECTION_STATE *Tcp4State ,
EFI_TCP4_CONFIG_DATA *Tcp4ConfigData ,
EFI_IP4_MODE_DATA *Ip4ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_TCP4_CONFIGURE)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_CONFIG_DATA *TcpConfigData
);
typedef
EFI_STATUS
( *EFI_TCP4_ROUTES)(
EFI_TCP4_PROTOCOL *This,
BOOLEAN DeleteRoute,
EFI_IPv4_ADDRESS *SubnetAddress,
EFI_IPv4_ADDRESS *SubnetMask,
EFI_IPv4_ADDRESS *GatewayAddress
);
typedef
EFI_STATUS
( *EFI_TCP4_CONNECT)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_CONNECTION_TOKEN *ConnectionToken
);
typedef
EFI_STATUS
( *EFI_TCP4_ACCEPT)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_LISTEN_TOKEN *ListenToken
);
typedef
EFI_STATUS
( *EFI_TCP4_TRANSMIT)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_IO_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP4_RECEIVE)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_IO_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP4_CLOSE)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_CLOSE_TOKEN *CloseToken
);
typedef
EFI_STATUS
( *EFI_TCP4_CANCEL)(
EFI_TCP4_PROTOCOL *This,
EFI_TCP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP4_POLL)(
EFI_TCP4_PROTOCOL *This
);
struct _EFI_TCP4_PROTOCOL {
EFI_TCP4_GET_MODE_DATA GetModeData;
EFI_TCP4_CONFIGURE Configure;
EFI_TCP4_ROUTES Routes;
EFI_TCP4_CONNECT Connect;
EFI_TCP4_ACCEPT Accept;
EFI_TCP4_TRANSMIT Transmit;
EFI_TCP4_RECEIVE Receive;
EFI_TCP4_CLOSE Close;
EFI_TCP4_CANCEL Cancel;
EFI_TCP4_POLL Poll;
};

extern EFI_GUID gEfiTcp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiTcp4ProtocolGuid;
typedef struct _EFI_TCP6_PROTOCOL EFI_TCP6_PROTOCOL;

typedef struct {

EFI_HANDLE InstanceHandle;

EFI_IPv6_ADDRESS LocalAddress;

UINT16 LocalPort;

EFI_IPv6_ADDRESS RemoteAddress;

UINT16 RemotePort;
} EFI_TCP6_SERVICE_POINT;

typedef struct {
EFI_HANDLE DriverHandle;
UINT32 ServiceCount;
EFI_TCP6_SERVICE_POINT Services[1];
} EFI_TCP6_VARIABLE_DATA;

typedef struct {
EFI_IPv6_ADDRESS StationAddress;

UINT16 StationPort;
EFI_IPv6_ADDRESS RemoteAddress;
UINT16 RemotePort;

BOOLEAN ActiveFlag;
} EFI_TCP6_ACCESS_POINT;

typedef struct {

UINT32 ReceiveBufferSize;

UINT32 SendBufferSize;

UINT32 MaxSynBackLog;

UINT32 ConnectionTimeout;

UINT32 DataRetries;
UINT32 FinTimeout;

UINT32 TimeWaitTimeout;

UINT32 KeepAliveProbes;

UINT32 KeepAliveTime;

UINT32 KeepAliveInterval;

BOOLEAN EnableNagle;

BOOLEAN EnableTimeStamp;

BOOLEAN EnableWindowScaling;

BOOLEAN EnableSelectiveAck;

BOOLEAN EnablePathMtuDiscovery;
} EFI_TCP6_OPTION;

typedef struct {

UINT8 TrafficClass;

UINT8 HopLimit;

EFI_TCP6_ACCESS_POINT AccessPoint;

EFI_TCP6_OPTION *ControlOption;
} EFI_TCP6_CONFIG_DATA;

typedef enum {
Tcp6StateClosed = 0,
Tcp6StateListen = 1,
Tcp6StateSynSent = 2,
Tcp6StateSynReceived = 3,
Tcp6StateEstablished = 4,
Tcp6StateFinWait1 = 5,
Tcp6StateFinWait2 = 6,
Tcp6StateClosing = 7,
Tcp6StateTimeWait = 8,
Tcp6StateCloseWait = 9,
Tcp6StateLastAck = 10
} EFI_TCP6_CONNECTION_STATE;

typedef struct {

EFI_EVENT Event;

EFI_STATUS Status;
} EFI_TCP6_COMPLETION_TOKEN;

typedef struct {
EFI_TCP6_COMPLETION_TOKEN CompletionToken;
} EFI_TCP6_CONNECTION_TOKEN;

typedef struct {
EFI_TCP6_COMPLETION_TOKEN CompletionToken;
EFI_HANDLE NewChildHandle;
} EFI_TCP6_LISTEN_TOKEN;

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_TCP6_FRAGMENT_DATA;

typedef struct {

BOOLEAN UrgentFlag;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_TCP6_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP6_RECEIVE_DATA;

typedef struct {

BOOLEAN Push;

BOOLEAN Urgent;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_TCP6_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP6_TRANSMIT_DATA;

typedef struct {
EFI_TCP6_COMPLETION_TOKEN CompletionToken;
union {

EFI_TCP6_RECEIVE_DATA *RxData;

EFI_TCP6_TRANSMIT_DATA *TxData;
} Packet;
} EFI_TCP6_IO_TOKEN;

typedef struct {

EFI_TCP6_COMPLETION_TOKEN CompletionToken;

BOOLEAN AbortOnClose;
} EFI_TCP6_CLOSE_TOKEN;
typedef
EFI_STATUS
( *EFI_TCP6_GET_MODE_DATA)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_CONNECTION_STATE *Tcp6State ,
EFI_TCP6_CONFIG_DATA *Tcp6ConfigData ,
EFI_IP6_MODE_DATA *Ip6ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_TCP6_CONFIGURE)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_CONFIG_DATA *Tcp6ConfigData
);
typedef
EFI_STATUS
( *EFI_TCP6_CONNECT)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_CONNECTION_TOKEN *ConnectionToken
);
typedef
EFI_STATUS
( *EFI_TCP6_ACCEPT)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_LISTEN_TOKEN *ListenToken
);
typedef
EFI_STATUS
( *EFI_TCP6_TRANSMIT)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_IO_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP6_RECEIVE)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_IO_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP6_CLOSE)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_CLOSE_TOKEN *CloseToken
);
typedef
EFI_STATUS
( *EFI_TCP6_CANCEL)(
EFI_TCP6_PROTOCOL *This,
EFI_TCP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_TCP6_POLL)(
EFI_TCP6_PROTOCOL *This
);
struct _EFI_TCP6_PROTOCOL {
EFI_TCP6_GET_MODE_DATA GetModeData;
EFI_TCP6_CONFIGURE Configure;
EFI_TCP6_CONNECT Connect;
EFI_TCP6_ACCEPT Accept;
EFI_TCP6_TRANSMIT Transmit;
EFI_TCP6_RECEIVE Receive;
EFI_TCP6_CLOSE Close;
EFI_TCP6_CANCEL Cancel;
EFI_TCP6_POLL Poll;
};

extern EFI_GUID gEfiTcp6ServiceBindingProtocolGuid;
extern EFI_GUID gEfiTcp6ProtocolGuid;
typedef struct _EFI_TIMER_ARCH_PROTOCOL EFI_TIMER_ARCH_PROTOCOL;
typedef
void
( *EFI_TIMER_NOTIFY)(
UINT64 Time
);
typedef
EFI_STATUS
( *EFI_TIMER_REGISTER_HANDLER)(
EFI_TIMER_ARCH_PROTOCOL *This,
EFI_TIMER_NOTIFY NotifyFunction
);
typedef
EFI_STATUS
( *EFI_TIMER_SET_TIMER_PERIOD)(
EFI_TIMER_ARCH_PROTOCOL *This,
UINT64 TimerPeriod
);
typedef
EFI_STATUS
( *EFI_TIMER_GET_TIMER_PERIOD)(
EFI_TIMER_ARCH_PROTOCOL *This,
UINT64 *TimerPeriod
);
typedef
EFI_STATUS
( *EFI_TIMER_GENERATE_SOFT_INTERRUPT)(
EFI_TIMER_ARCH_PROTOCOL *This
);
struct _EFI_TIMER_ARCH_PROTOCOL {
EFI_TIMER_REGISTER_HANDLER RegisterHandler;
EFI_TIMER_SET_TIMER_PERIOD SetTimerPeriod;
EFI_TIMER_GET_TIMER_PERIOD GetTimerPeriod;
EFI_TIMER_GENERATE_SOFT_INTERRUPT GenerateSoftInterrupt;
};

extern EFI_GUID gEfiTimerArchProtocolGuid;
typedef struct _EFI_UDP4_PROTOCOL EFI_UDP4_PROTOCOL;

typedef struct {
EFI_HANDLE InstanceHandle;
EFI_IPv4_ADDRESS LocalAddress;
UINT16 LocalPort;
EFI_IPv4_ADDRESS RemoteAddress;
UINT16 RemotePort;
} EFI_UDP4_SERVICE_POINT;

typedef struct {
EFI_HANDLE DriverHandle;
UINT32 ServiceCount;
EFI_UDP4_SERVICE_POINT Services[1];
} EFI_UDP4_VARIABLE_DATA;

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_UDP4_FRAGMENT_DATA;

typedef struct {
EFI_IPv4_ADDRESS SourceAddress;
UINT16 SourcePort;
EFI_IPv4_ADDRESS DestinationAddress;
UINT16 DestinationPort;
} EFI_UDP4_SESSION_DATA;
typedef struct {

BOOLEAN AcceptBroadcast;
BOOLEAN AcceptPromiscuous;
BOOLEAN AcceptAnyPort;
BOOLEAN AllowDuplicatePort;

UINT8 TypeOfService;
UINT8 TimeToLive;
BOOLEAN DoNotFragment;
UINT32 ReceiveTimeout;
UINT32 TransmitTimeout;

BOOLEAN UseDefaultAddress;
EFI_IPv4_ADDRESS StationAddress;
EFI_IPv4_ADDRESS SubnetMask;
UINT16 StationPort;
EFI_IPv4_ADDRESS RemoteAddress;
UINT16 RemotePort;
} EFI_UDP4_CONFIG_DATA;

typedef struct {
EFI_UDP4_SESSION_DATA *UdpSessionData;
EFI_IPv4_ADDRESS *GatewayAddress;
UINT32 DataLength;
UINT32 FragmentCount;
EFI_UDP4_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP4_TRANSMIT_DATA;

typedef struct {
EFI_TIME TimeStamp;
EFI_EVENT RecycleSignal;
EFI_UDP4_SESSION_DATA UdpSession;
UINT32 DataLength;
UINT32 FragmentCount;
EFI_UDP4_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP4_RECEIVE_DATA;

typedef struct {
EFI_EVENT Event;
EFI_STATUS Status;
union {
EFI_UDP4_RECEIVE_DATA *RxData;
EFI_UDP4_TRANSMIT_DATA *TxData;
} Packet;
} EFI_UDP4_COMPLETION_TOKEN;
typedef
EFI_STATUS
( *EFI_UDP4_GET_MODE_DATA)(
EFI_UDP4_PROTOCOL *This,
EFI_UDP4_CONFIG_DATA *Udp4ConfigData ,
EFI_IP4_MODE_DATA *Ip4ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_UDP4_CONFIGURE)(
EFI_UDP4_PROTOCOL *This,
EFI_UDP4_CONFIG_DATA *UdpConfigData
);
typedef
EFI_STATUS
( *EFI_UDP4_GROUPS)(
EFI_UDP4_PROTOCOL *This,
BOOLEAN JoinFlag,
EFI_IPv4_ADDRESS *MulticastAddress
);
typedef
EFI_STATUS
( *EFI_UDP4_ROUTES)(
EFI_UDP4_PROTOCOL *This,
BOOLEAN DeleteRoute,
EFI_IPv4_ADDRESS *SubnetAddress,
EFI_IPv4_ADDRESS *SubnetMask,
EFI_IPv4_ADDRESS *GatewayAddress
);
typedef
EFI_STATUS
( *EFI_UDP4_POLL)(
EFI_UDP4_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_UDP4_RECEIVE)(
EFI_UDP4_PROTOCOL *This,
EFI_UDP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_UDP4_TRANSMIT)(
EFI_UDP4_PROTOCOL *This,
EFI_UDP4_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_UDP4_CANCEL)(
EFI_UDP4_PROTOCOL *This,
EFI_UDP4_COMPLETION_TOKEN *Token
);
struct _EFI_UDP4_PROTOCOL {
EFI_UDP4_GET_MODE_DATA GetModeData;
EFI_UDP4_CONFIGURE Configure;
EFI_UDP4_GROUPS Groups;
EFI_UDP4_ROUTES Routes;
EFI_UDP4_TRANSMIT Transmit;
EFI_UDP4_RECEIVE Receive;
EFI_UDP4_CANCEL Cancel;
EFI_UDP4_POLL Poll;
};

extern EFI_GUID gEfiUdp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiUdp4ProtocolGuid;
typedef struct {

EFI_HANDLE InstanceHandle;

EFI_IPv6_ADDRESS LocalAddress;

UINT16 LocalPort;

EFI_IPv6_ADDRESS RemoteAddress;

UINT16 RemotePort;
} EFI_UDP6_SERVICE_POINT;

typedef struct {

EFI_HANDLE DriverHandle;

UINT32 ServiceCount;

EFI_UDP6_SERVICE_POINT Services[1];
} EFI_UDP6_VARIABLE_DATA;

typedef struct _EFI_UDP6_PROTOCOL EFI_UDP6_PROTOCOL;

typedef struct {
UINT32 FragmentLength;
void *FragmentBuffer;
} EFI_UDP6_FRAGMENT_DATA;

typedef struct {

EFI_IPv6_ADDRESS SourceAddress;

UINT16 SourcePort;

EFI_IPv6_ADDRESS DestinationAddress;

UINT16 DestinationPort;
} EFI_UDP6_SESSION_DATA;

typedef struct {

BOOLEAN AcceptPromiscuous;

BOOLEAN AcceptAnyPort;

BOOLEAN AllowDuplicatePort;

UINT8 TrafficClass;

UINT8 HopLimit;

UINT32 ReceiveTimeout;

UINT32 TransmitTimeout;
EFI_IPv6_ADDRESS StationAddress;

UINT16 StationPort;

EFI_IPv6_ADDRESS RemoteAddress;

UINT16 RemotePort;
} EFI_UDP6_CONFIG_DATA;

typedef struct {

EFI_UDP6_SESSION_DATA *UdpSessionData;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_UDP6_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP6_TRANSMIT_DATA;
typedef struct {

EFI_TIME TimeStamp;

EFI_EVENT RecycleSignal;

EFI_UDP6_SESSION_DATA UdpSession;

UINT32 DataLength;

UINT32 FragmentCount;

EFI_UDP6_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP6_RECEIVE_DATA;
typedef struct {

EFI_EVENT Event;
EFI_STATUS Status;
union {

EFI_UDP6_RECEIVE_DATA *RxData;

EFI_UDP6_TRANSMIT_DATA *TxData;
} Packet;
} EFI_UDP6_COMPLETION_TOKEN;
typedef
EFI_STATUS
( *EFI_UDP6_GET_MODE_DATA)(
EFI_UDP6_PROTOCOL *This,
EFI_UDP6_CONFIG_DATA *Udp6ConfigData ,
EFI_IP6_MODE_DATA *Ip6ModeData ,
EFI_MANAGED_NETWORK_CONFIG_DATA *MnpConfigData ,
EFI_SIMPLE_NETWORK_MODE *SnpModeData
);
typedef
EFI_STATUS
( *EFI_UDP6_CONFIGURE)(
EFI_UDP6_PROTOCOL *This,
EFI_UDP6_CONFIG_DATA *UdpConfigData
);
typedef
EFI_STATUS
( *EFI_UDP6_GROUPS)(
EFI_UDP6_PROTOCOL *This,
BOOLEAN JoinFlag,
EFI_IPv6_ADDRESS *MulticastAddress
);
typedef
EFI_STATUS
( *EFI_UDP6_TRANSMIT)(
EFI_UDP6_PROTOCOL *This,
EFI_UDP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_UDP6_RECEIVE)(
EFI_UDP6_PROTOCOL *This,
EFI_UDP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_UDP6_CANCEL)(
EFI_UDP6_PROTOCOL *This,
EFI_UDP6_COMPLETION_TOKEN *Token
);
typedef
EFI_STATUS
( *EFI_UDP6_POLL)(
EFI_UDP6_PROTOCOL *This
);

struct _EFI_UDP6_PROTOCOL {
EFI_UDP6_GET_MODE_DATA GetModeData;
EFI_UDP6_CONFIGURE Configure;
EFI_UDP6_GROUPS Groups;
EFI_UDP6_TRANSMIT Transmit;
EFI_UDP6_RECEIVE Receive;
EFI_UDP6_CANCEL Cancel;
EFI_UDP6_POLL Poll;
};

extern EFI_GUID gEfiUdp6ServiceBindingProtocolGuid;
extern EFI_GUID gEfiUdp6ProtocolGuid;
typedef struct _EFI_UGA_DRAW_PROTOCOL EFI_UGA_DRAW_PROTOCOL;
typedef
EFI_STATUS
( *EFI_UGA_DRAW_PROTOCOL_GET_MODE)(
EFI_UGA_DRAW_PROTOCOL *This,
UINT32 *HorizontalResolution,
UINT32 *VerticalResolution,
UINT32 *ColorDepth,
UINT32 *RefreshRate
);
typedef
EFI_STATUS
( *EFI_UGA_DRAW_PROTOCOL_SET_MODE)(
EFI_UGA_DRAW_PROTOCOL *This,
UINT32 HorizontalResolution,
UINT32 VerticalResolution,
UINT32 ColorDepth,
UINT32 RefreshRate
);

typedef struct {
UINT8 Blue;
UINT8 Green;
UINT8 Red;
UINT8 Reserved;
} EFI_UGA_PIXEL;

typedef union {
EFI_UGA_PIXEL Pixel;
UINT32 Raw;
} EFI_UGA_PIXEL_UNION;

typedef enum {
EfiUgaVideoFill,

EfiUgaVideoToBltBuffer,

EfiUgaBltBufferToVideo,

EfiUgaVideoToVideo,

EfiUgaBltMax

} EFI_UGA_BLT_OPERATION;
typedef
EFI_STATUS
( *EFI_UGA_DRAW_PROTOCOL_BLT)(
EFI_UGA_DRAW_PROTOCOL * This,
EFI_UGA_PIXEL * BltBuffer,
EFI_UGA_BLT_OPERATION BltOperation,
UINTN SourceX,
UINTN SourceY,
UINTN DestinationX,
UINTN DestinationY,
UINTN Width,
UINTN Height,
UINTN Delta
);

struct _EFI_UGA_DRAW_PROTOCOL {
EFI_UGA_DRAW_PROTOCOL_GET_MODE GetMode;
EFI_UGA_DRAW_PROTOCOL_SET_MODE SetMode;
EFI_UGA_DRAW_PROTOCOL_BLT Blt;
};

extern EFI_GUID gEfiUgaDrawProtocolGuid;
typedef struct _EFI_UGA_IO_PROTOCOL EFI_UGA_IO_PROTOCOL;

typedef UINT32 UGA_STATUS;

typedef enum {
UgaDtParentBus = 1,
UgaDtGraphicsController,
UgaDtOutputController,
UgaDtOutputPort,
UgaDtOther
} UGA_DEVICE_TYPE, *PUGA_DEVICE_TYPE;

typedef UINT32 UGA_DEVICE_ID, *PUGA_DEVICE_ID;

typedef struct {
UGA_DEVICE_TYPE deviceType;
UGA_DEVICE_ID deviceId;
UINT32 ui32DeviceContextSize;
UINT32 ui32SharedContextSize;
} UGA_DEVICE_DATA, *PUGA_DEVICE_DATA;

typedef struct _UGA_DEVICE {
void *pvDeviceContext;
void *pvSharedContext;
void *pvRunTimeContext;
struct _UGA_DEVICE *pParentDevice;
void *pvBusIoServices;
void *pvStdIoServices;
UGA_DEVICE_DATA deviceData;
} UGA_DEVICE, *PUGA_DEVICE;

typedef enum {
UgaIoGetVersion = 1,
UgaIoGetChildDevice,
UgaIoStartDevice,
UgaIoStopDevice,
UgaIoFlushDevice,
UgaIoResetDevice,
UgaIoGetDeviceState,
UgaIoSetDeviceState,
UgaIoSetPowerState,
UgaIoGetMemoryConfiguration,
UgaIoSetVideoMode,
UgaIoCopyRectangle,
UgaIoGetEdidSegment,
UgaIoDeviceChannelOpen,
UgaIoDeviceChannelClose,
UgaIoDeviceChannelRead,
UgaIoDeviceChannelWrite,
UgaIoGetPersistentDataSize,
UgaIoGetPersistentData,
UgaIoSetPersistentData,
UgaIoGetDevicePropertySize,
UgaIoGetDeviceProperty,
UgaIoBtPrivateInterface
} UGA_IO_REQUEST_CODE, *PUGA_IO_REQUEST_CODE;

typedef struct {
UGA_IO_REQUEST_CODE ioRequestCode;
void *pvInBuffer;
UINT64 ui64InBufferSize;
void *pvOutBuffer;
UINT64 ui64OutBufferSize;
UINT64 ui64BytesReturned;
} UGA_IO_REQUEST, *PUGA_IO_REQUEST;
typedef
EFI_STATUS
( *EFI_UGA_IO_PROTOCOL_CREATE_DEVICE)(
EFI_UGA_IO_PROTOCOL *This,
UGA_DEVICE *ParentDevice,
UGA_DEVICE_DATA *DeviceData,
void *RunTimeContext,
UGA_DEVICE **Device
);
typedef
EFI_STATUS
( *EFI_UGA_IO_PROTOCOL_DELETE_DEVICE)(
EFI_UGA_IO_PROTOCOL * This,
UGA_DEVICE * Device
);
typedef UGA_STATUS
( *PUGA_FW_SERVICE_DISPATCH)(
PUGA_DEVICE pDevice,
PUGA_IO_REQUEST pIoRequest
);

struct _EFI_UGA_IO_PROTOCOL {
EFI_UGA_IO_PROTOCOL_CREATE_DEVICE CreateDevice;
EFI_UGA_IO_PROTOCOL_DELETE_DEVICE DeleteDevice;
PUGA_FW_SERVICE_DISPATCH DispatchService;
};

extern EFI_GUID gEfiUgaIoProtocolGuid;

typedef struct {
UINT32 Version;
UINT32 HeaderSize;
UINT32 SizeOfEntries;
UINT32 NumberOfEntries;
} EFI_DRIVER_OS_HANDOFF_HEADER;

typedef enum {
EfiUgaDriverFromPciRom,
EfiUgaDriverFromSystem,
EfiDriverHandoffMax
} EFI_DRIVER_HANOFF_ENUM;

typedef struct {
EFI_DRIVER_HANOFF_ENUM Type;
EFI_DEVICE_PATH_PROTOCOL *DevicePath;
void *PciRomImage;
UINT64 PciRomSize;
} EFI_DRIVER_OS_HANDOFF;
typedef struct _EFI_UNICODE_COLLATION_PROTOCOL EFI_UNICODE_COLLATION_PROTOCOL;
typedef EFI_UNICODE_COLLATION_PROTOCOL UNICODE_COLLATION_INTERFACE;
typedef
INTN
( *EFI_UNICODE_COLLATION_STRICOLL)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
CHAR16 *Str1,
CHAR16 *Str2
);
typedef
BOOLEAN
( *EFI_UNICODE_COLLATION_METAIMATCH)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
CHAR16 *String,
CHAR16 *Pattern
);
typedef
void
( *EFI_UNICODE_COLLATION_STRLWR)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
CHAR16 *Str
);
typedef
void
( *EFI_UNICODE_COLLATION_STRUPR)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
CHAR16 *Str
);
typedef
void
( *EFI_UNICODE_COLLATION_FATTOSTR)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
UINTN FatSize,
CHAR8 *Fat,
CHAR16 *String
);
typedef
BOOLEAN
( *EFI_UNICODE_COLLATION_STRTOFAT)(
EFI_UNICODE_COLLATION_PROTOCOL *This,
CHAR16 *String,
UINTN FatSize,
CHAR8 *Fat
);

struct _EFI_UNICODE_COLLATION_PROTOCOL {
EFI_UNICODE_COLLATION_STRICOLL StriColl;
EFI_UNICODE_COLLATION_METAIMATCH MetaiMatch;
EFI_UNICODE_COLLATION_STRLWR StrLwr;
EFI_UNICODE_COLLATION_STRUPR StrUpr;

EFI_UNICODE_COLLATION_FATTOSTR FatToStr;
EFI_UNICODE_COLLATION_STRTOFAT StrToFat;

CHAR8 *SupportedLanguages;
};

extern EFI_GUID gEfiUnicodeCollationProtocolGuid;
extern EFI_GUID gEfiUnicodeCollation2ProtocolGuid;
#pragma pack(1)

typedef struct {
UINT8 RequestType;
UINT8 Request;
UINT16 Value;
UINT16 Index;
UINT16 Length;
} USB_DEVICE_REQUEST;

typedef struct {
UINT8 Length;
UINT8 DescriptorType;
UINT16 BcdUSB;
UINT8 DeviceClass;
UINT8 DeviceSubClass;
UINT8 DeviceProtocol;
UINT8 MaxPacketSize0;
UINT16 IdVendor;
UINT16 IdProduct;
UINT16 BcdDevice;
UINT8 StrManufacturer;
UINT8 StrProduct;
UINT8 StrSerialNumber;
UINT8 NumConfigurations;
} USB_DEVICE_DESCRIPTOR;

typedef struct {
UINT8 Length;
UINT8 DescriptorType;
UINT16 TotalLength;
UINT8 NumInterfaces;
UINT8 ConfigurationValue;
UINT8 Configuration;
UINT8 Attributes;
UINT8 MaxPower;
} USB_CONFIG_DESCRIPTOR;

typedef struct {
UINT8 Length;
UINT8 DescriptorType;
UINT8 InterfaceNumber;
UINT8 AlternateSetting;
UINT8 NumEndpoints;
UINT8 InterfaceClass;
UINT8 InterfaceSubClass;
UINT8 InterfaceProtocol;
UINT8 Interface;
} USB_INTERFACE_DESCRIPTOR;

typedef struct {
UINT8 Length;
UINT8 DescriptorType;
UINT8 EndpointAddress;
UINT8 Attributes;
UINT16 MaxPacketSize;
UINT8 Interval;
} USB_ENDPOINT_DESCRIPTOR;

typedef struct {
UINT8 Length;
UINT8 DescriptorType;
CHAR16 String[1];
} EFI_USB_STRING_DESCRIPTOR;

#pragma pack()

typedef enum {

USB_REQ_TYPE_STANDARD = (0x00 << 5),
USB_REQ_TYPE_CLASS = (0x01 << 5),
USB_REQ_TYPE_VENDOR = (0x02 << 5),

USB_REQ_GET_STATUS = 0x00,
USB_REQ_CLEAR_FEATURE = 0x01,
USB_REQ_SET_FEATURE = 0x03,
USB_REQ_SET_ADDRESS = 0x05,
USB_REQ_GET_DESCRIPTOR = 0x06,
USB_REQ_SET_DESCRIPTOR = 0x07,
USB_REQ_GET_CONFIG = 0x08,
USB_REQ_SET_CONFIG = 0x09,
USB_REQ_GET_INTERFACE = 0x0A,
USB_REQ_SET_INTERFACE = 0x0B,
USB_REQ_SYNCH_FRAME = 0x0C,

USB_TARGET_DEVICE = 0,
USB_TARGET_INTERFACE = 0x01,
USB_TARGET_ENDPOINT = 0x02,
USB_TARGET_OTHER = 0x03,

USB_DESC_TYPE_DEVICE = 0x01,
USB_DESC_TYPE_CONFIG = 0x02,
USB_DESC_TYPE_STRING = 0x03,
USB_DESC_TYPE_INTERFACE = 0x04,
USB_DESC_TYPE_ENDPOINT = 0x05,
USB_DESC_TYPE_HID = 0x21,
USB_DESC_TYPE_REPORT = 0x22,

USB_FEATURE_ENDPOINT_HALT = 0,

USB_ENDPOINT_CONTROL = 0x00,
USB_ENDPOINT_ISO = 0x01,
USB_ENDPOINT_BULK = 0x02,
USB_ENDPOINT_INTERRUPT = 0x03,

USB_ENDPOINT_TYPE_MASK = 0x03,
USB_ENDPOINT_DIR_IN = 0x80,

EFI_USB_INTERRUPT_DELAY = 2000000
} USB_TYPES_DEFINITION;
#pragma pack(1)

typedef struct hid_class_descriptor {
UINT8 DescriptorType;
UINT16 DescriptorLength;
} EFI_USB_HID_CLASS_DESCRIPTOR;

typedef struct hid_descriptor {
UINT8 Length;
UINT8 DescriptorType;
UINT16 BcdHID;
UINT8 CountryCode;
UINT8 NumDescriptors;
EFI_USB_HID_CLASS_DESCRIPTOR HidClassDesc[1];
} EFI_USB_HID_DESCRIPTOR;

#pragma pack()
typedef struct _EFI_USB_IO_PROTOCOL EFI_USB_IO_PROTOCOL;
typedef USB_DEVICE_REQUEST EFI_USB_DEVICE_REQUEST;
typedef USB_DEVICE_DESCRIPTOR EFI_USB_DEVICE_DESCRIPTOR;
typedef USB_CONFIG_DESCRIPTOR EFI_USB_CONFIG_DESCRIPTOR;
typedef USB_INTERFACE_DESCRIPTOR EFI_USB_INTERFACE_DESCRIPTOR;
typedef USB_ENDPOINT_DESCRIPTOR EFI_USB_ENDPOINT_DESCRIPTOR;

typedef enum {
EfiUsbDataIn,
EfiUsbDataOut,
EfiUsbNoData
} EFI_USB_DATA_DIRECTION;
typedef
EFI_STATUS
( *EFI_ASYNC_USB_TRANSFER_CALLBACK)(
void *Data,
UINTN DataLength,
void *Context,
UINT32 Status
);
typedef
EFI_STATUS
( *EFI_USB_IO_CONTROL_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
EFI_USB_DEVICE_REQUEST *Request,
EFI_USB_DATA_DIRECTION Direction,
UINT32 Timeout,
void *Data ,
UINTN DataLength ,
UINT32 *Status
);
typedef
EFI_STATUS
( *EFI_USB_IO_BULK_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
UINT8 DeviceEndpoint,
void *Data,
UINTN *DataLength,
UINTN Timeout,
UINT32 *Status
);
typedef
EFI_STATUS
( *EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
UINT8 DeviceEndpoint,
BOOLEAN IsNewTransfer,
UINTN PollingInterval ,
UINTN DataLength ,
EFI_ASYNC_USB_TRANSFER_CALLBACK InterruptCallBack ,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB_IO_SYNC_INTERRUPT_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
UINT8 DeviceEndpoint,
void *Data,
UINTN *DataLength,
UINTN Timeout,
UINT32 *Status
);
typedef
EFI_STATUS
( *EFI_USB_IO_ISOCHRONOUS_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
UINT8 DeviceEndpoint,
void *Data,
UINTN DataLength,
UINT32 *Status
);
typedef
EFI_STATUS
( *EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER)(
EFI_USB_IO_PROTOCOL *This,
UINT8 DeviceEndpoint,
void *Data,
UINTN DataLength,
EFI_ASYNC_USB_TRANSFER_CALLBACK IsochronousCallBack,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB_IO_PORT_RESET)(
EFI_USB_IO_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_DEVICE_DESCRIPTOR)(
EFI_USB_IO_PROTOCOL *This,
EFI_USB_DEVICE_DESCRIPTOR *DeviceDescriptor
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_CONFIG_DESCRIPTOR)(
EFI_USB_IO_PROTOCOL *This,
EFI_USB_CONFIG_DESCRIPTOR *ConfigurationDescriptor
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_INTERFACE_DESCRIPTOR)(
EFI_USB_IO_PROTOCOL *This,
EFI_USB_INTERFACE_DESCRIPTOR *InterfaceDescriptor
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR)(
EFI_USB_IO_PROTOCOL *This,
UINT8 EndpointIndex,
EFI_USB_ENDPOINT_DESCRIPTOR *EndpointDescriptor
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_STRING_DESCRIPTOR)(
EFI_USB_IO_PROTOCOL *This,
UINT16 LangID,
UINT8 StringID,
CHAR16 **String
);
typedef
EFI_STATUS
( *EFI_USB_IO_GET_SUPPORTED_LANGUAGE)(
EFI_USB_IO_PROTOCOL *This,
UINT16 **LangIDTable,
UINT16 *TableSize
);
struct _EFI_USB_IO_PROTOCOL {

EFI_USB_IO_CONTROL_TRANSFER UsbControlTransfer;
EFI_USB_IO_BULK_TRANSFER UsbBulkTransfer;
EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER UsbAsyncInterruptTransfer;
EFI_USB_IO_SYNC_INTERRUPT_TRANSFER UsbSyncInterruptTransfer;
EFI_USB_IO_ISOCHRONOUS_TRANSFER UsbIsochronousTransfer;
EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER UsbAsyncIsochronousTransfer;

EFI_USB_IO_GET_DEVICE_DESCRIPTOR UsbGetDeviceDescriptor;
EFI_USB_IO_GET_CONFIG_DESCRIPTOR UsbGetConfigDescriptor;
EFI_USB_IO_GET_INTERFACE_DESCRIPTOR UsbGetInterfaceDescriptor;
EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR UsbGetEndpointDescriptor;
EFI_USB_IO_GET_STRING_DESCRIPTOR UsbGetStringDescriptor;
EFI_USB_IO_GET_SUPPORTED_LANGUAGE UsbGetSupportedLanguages;

EFI_USB_IO_PORT_RESET UsbPortReset;
};

extern EFI_GUID gEfiUsbIoProtocolGuid;
typedef struct _EFI_USB2_HC_PROTOCOL EFI_USB2_HC_PROTOCOL;

typedef struct {
UINT16 PortStatus;
UINT16 PortChangeStatus;
} EFI_USB_PORT_STATUS;
typedef enum {
EfiUsbPortEnable = 1,
EfiUsbPortSuspend = 2,
EfiUsbPortReset = 4,
EfiUsbPortPower = 8,
EfiUsbPortOwner = 13,
EfiUsbPortConnectChange = 16,
EfiUsbPortEnableChange = 17,
EfiUsbPortSuspendChange = 18,
EfiUsbPortOverCurrentChange = 19,
EfiUsbPortResetChange = 20
} EFI_USB_PORT_FEATURE;

typedef struct {
UINT8 TranslatorHubAddress;
UINT8 TranslatorPortNumber;
} EFI_USB2_HC_TRANSACTION_TRANSLATOR;
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_GET_CAPABILITY)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 *MaxSpeed,
UINT8 *PortNumber,
UINT8 *Is64BitCapable
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_RESET)(
EFI_USB2_HC_PROTOCOL *This,
UINT16 Attributes
);

typedef enum {
EfiUsbHcStateHalt,
EfiUsbHcStateOperational,

EfiUsbHcStateSuspend,
EfiUsbHcStateMaximum
} EFI_USB_HC_STATE;
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_GET_STATE)(
EFI_USB2_HC_PROTOCOL *This,
EFI_USB_HC_STATE *State
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_SET_STATE)(
EFI_USB2_HC_PROTOCOL *This,
EFI_USB_HC_STATE State
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 DeviceSpeed,
UINTN MaximumPacketLength,
EFI_USB_DEVICE_REQUEST *Request,
EFI_USB_DATA_DIRECTION TransferDirection,
void *Data ,
UINTN *DataLength ,
UINTN TimeOut,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_BULK_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 DeviceSpeed,
UINTN MaximumPacketLength,
UINT8 DataBuffersNumber,
void *Data[10],
UINTN *DataLength,
UINT8 *DataToggle,
UINTN TimeOut,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 DeviceSpeed,
UINTN MaxiumPacketLength,
BOOLEAN IsNewTransfer,
UINT8 *DataToggle,
UINTN PollingInterval ,
UINTN DataLength ,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator ,
EFI_ASYNC_USB_TRANSFER_CALLBACK CallBackFunction ,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 DeviceSpeed,
UINTN MaximumPacketLength,
void *Data,
UINTN *DataLength,
UINT8 *DataToggle,
UINTN TimeOut,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 DeviceSpeed,
UINTN MaximumPacketLength,
UINT8 DataBuffersNumber,
void *Data[7],
UINTN DataLength,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 DeviceSpeed,
UINTN MaximumPacketLength,
UINT8 DataBuffersNumber,
void *Data[7],
UINTN DataLength,
EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
EFI_ASYNC_USB_TRANSFER_CALLBACK IsochronousCallBack,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_STATUS *PortStatus
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_FEATURE PortFeature
);
typedef
EFI_STATUS
( *EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE)(
EFI_USB2_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_FEATURE PortFeature
);
struct _EFI_USB2_HC_PROTOCOL {
EFI_USB2_HC_PROTOCOL_GET_CAPABILITY GetCapability;
EFI_USB2_HC_PROTOCOL_RESET Reset;
EFI_USB2_HC_PROTOCOL_GET_STATE GetState;
EFI_USB2_HC_PROTOCOL_SET_STATE SetState;
EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER ControlTransfer;
EFI_USB2_HC_PROTOCOL_BULK_TRANSFER BulkTransfer;
EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER AsyncInterruptTransfer;
EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER SyncInterruptTransfer;
EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER IsochronousTransfer;
EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER AsyncIsochronousTransfer;
EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS GetRootHubPortStatus;
EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE SetRootHubPortFeature;
EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE ClearRootHubPortFeature;

UINT16 MajorRevision;

UINT16 MinorRevision;
};

extern EFI_GUID gEfiUsb2HcProtocolGuid;
typedef struct _EFI_USB_HC_PROTOCOL EFI_USB_HC_PROTOCOL;
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_RESET)(
EFI_USB_HC_PROTOCOL *This,
UINT16 Attributes
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_GET_STATE)(
EFI_USB_HC_PROTOCOL *This,
EFI_USB_HC_STATE *State
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_SET_STATE)(
EFI_USB_HC_PROTOCOL *This,
EFI_USB_HC_STATE State
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_CONTROL_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
BOOLEAN IsSlowDevice,
UINT8 MaximumPacketLength,
EFI_USB_DEVICE_REQUEST *Request,
EFI_USB_DATA_DIRECTION TransferDirection,
void *Data ,
UINTN *DataLength ,
UINTN TimeOut,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_BULK_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 MaximumPacketLength,
void *Data,
UINTN *DataLength,
UINT8 *DataToggle,
UINTN TimeOut,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
BOOLEAN IsSlowDevice,
UINT8 MaxiumPacketLength,
BOOLEAN IsNewTransfer,
UINT8 *DataToggle,
UINTN PollingInterval ,
UINTN DataLength ,
EFI_ASYNC_USB_TRANSFER_CALLBACK CallBackFunction ,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
BOOLEAN IsSlowDevice,
UINT8 MaximumPacketLength,
void *Data,
UINTN *DataLength,
UINT8 *DataToggle,
UINTN TimeOut,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_ISOCHRONOUS_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 MaximumPacketLength,
void *Data,
UINTN DataLength,
UINT32 *TransferResult
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 DeviceAddress,
UINT8 EndPointAddress,
UINT8 MaximumPacketLength,
void *Data,
UINTN DataLength,
EFI_ASYNC_USB_TRANSFER_CALLBACK IsochronousCallBack,
void *Context
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_GET_ROOTHUB_PORT_NUMBER)(
EFI_USB_HC_PROTOCOL *This,
UINT8 *PortNumber
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS)(
EFI_USB_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_STATUS *PortStatus
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE)(
EFI_USB_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_FEATURE PortFeature
);
typedef
EFI_STATUS
( *EFI_USB_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE)(
EFI_USB_HC_PROTOCOL *This,
UINT8 PortNumber,
EFI_USB_PORT_FEATURE PortFeature
);
struct _EFI_USB_HC_PROTOCOL {
EFI_USB_HC_PROTOCOL_RESET Reset;
EFI_USB_HC_PROTOCOL_GET_STATE GetState;
EFI_USB_HC_PROTOCOL_SET_STATE SetState;
EFI_USB_HC_PROTOCOL_CONTROL_TRANSFER ControlTransfer;
EFI_USB_HC_PROTOCOL_BULK_TRANSFER BulkTransfer;
EFI_USB_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER AsyncInterruptTransfer;
EFI_USB_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER SyncInterruptTransfer;
EFI_USB_HC_PROTOCOL_ISOCHRONOUS_TRANSFER IsochronousTransfer;
EFI_USB_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER AsyncIsochronousTransfer;
EFI_USB_HC_PROTOCOL_GET_ROOTHUB_PORT_NUMBER GetRootHubPortNumber;
EFI_USB_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS GetRootHubPortStatus;
EFI_USB_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE SetRootHubPortFeature;
EFI_USB_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE ClearRootHubPortFeature;

UINT16 MajorRevision;

UINT16 MinorRevision;
};

extern EFI_GUID gEfiUsbHcProtocolGuid;

typedef void *EFI_USER_PROFILE_HANDLE;
typedef void *EFI_USER_INFO_HANDLE;

typedef UINT16 EFI_USER_INFO_ATTRIBS;
typedef struct {

EFI_GUID Credential;

UINT8 InfoType;

UINT8 Reserved1;

EFI_USER_INFO_ATTRIBS InfoAttribs;

UINT32 InfoSize;
} EFI_USER_INFO;
typedef UINT64 EFI_CREDENTIAL_CAPABILITIES;

typedef UINT32 EFI_CREDENTIAL_LOGON_FLAGS;
typedef CHAR16 *EFI_USER_INFO_NAME;

typedef EFI_TIME EFI_USER_INFO_CREATE_DATE;

typedef EFI_TIME EFI_USER_INFO_USAGE_DATE;

typedef UINT64 EFI_USER_INFO_USAGE_COUNT;

typedef UINT8 EFI_USER_INFO_IDENTIFIER[16];

typedef EFI_GUID EFI_USER_INFO_CREDENTIAL_TYPE;

typedef CHAR16 *EFI_USER_INFO_CREDENTIAL_TYPE_NAME;

typedef EFI_GUID EFI_USER_INFO_CREDENTIAL_PROVIDER;

typedef CHAR16 *EFI_USER_INFO_CREDENTIAL_PROVIDER_NAME;
typedef void *EFI_USER_INFO_CBEFF;

typedef UINT8 EFI_USER_INFO_FAR;

typedef UINT8 EFI_USER_INFO_RETRY;

typedef struct {
UINT32 Type;
UINT32 Size;
} EFI_USER_INFO_ACCESS_CONTROL;

typedef EFI_USER_INFO_ACCESS_CONTROL EFI_USER_INFO_ACCESS_POLICY;
typedef UINT32 EFI_USER_INFO_ACCESS_BOOT_ORDER_HDR;
typedef struct {
UINT32 Type;
UINT32 Length;
} EFI_USER_INFO_IDENTITY_POLICY;
typedef EFI_GUID EFI_USER_INFO_GUID;

typedef struct {
UINT64 Size;
} EFI_USER_INFO_TABLE;

typedef struct _EFI_USER_MANAGER_PROTOCOL EFI_USER_MANAGER_PROTOCOL;
typedef
EFI_STATUS
( *EFI_USER_PROFILE_CREATE)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE *User
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_DELETE)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_GET_NEXT)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE *User
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_CURRENT)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE *CurrentUser
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_IDENTIFY)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE *User
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_FIND)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE *User,
EFI_USER_INFO_HANDLE *UserInfo ,
EFI_USER_INFO *Info,
UINTN InfoSize
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_NOTIFY)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_HANDLE Changed
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_GET_INFO)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_HANDLE UserInfo,
EFI_USER_INFO *Info,
UINTN *InfoSize
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_SET_INFO)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_HANDLE *UserInfo,
EFI_USER_INFO *Info,
UINTN InfoSize
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_DELETE_INFO)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_HANDLE UserInfo
);
typedef
EFI_STATUS
( *EFI_USER_PROFILE_GET_NEXT_INFO)(
EFI_USER_MANAGER_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_HANDLE *UserInfo
);

struct _EFI_USER_MANAGER_PROTOCOL {
EFI_USER_PROFILE_CREATE Create;
EFI_USER_PROFILE_DELETE Delete;
EFI_USER_PROFILE_GET_NEXT GetNext;
EFI_USER_PROFILE_CURRENT Current;
EFI_USER_PROFILE_IDENTIFY Identify;
EFI_USER_PROFILE_FIND Find;
EFI_USER_PROFILE_NOTIFY Notify;
EFI_USER_PROFILE_GET_INFO GetInfo;
EFI_USER_PROFILE_SET_INFO SetInfo;
EFI_USER_PROFILE_DELETE_INFO DeleteInfo;
EFI_USER_PROFILE_GET_NEXT_INFO GetNextInfo;
};

extern EFI_GUID gEfiUserManagerProtocolGuid;
extern EFI_GUID gEfiEventUserProfileChangedGuid;
extern EFI_GUID gEfiUserCredentialClassUnknownGuid;
extern EFI_GUID gEfiUserCredentialClassPasswordGuid;
extern EFI_GUID gEfiUserCredentialClassSmartCardGuid;
extern EFI_GUID gEfiUserCredentialClassFingerprintGuid;
extern EFI_GUID gEfiUserCredentialClassHandprintGuid;
extern EFI_GUID gEfiUserCredentialClassSecureCardGuid;
extern EFI_GUID gEfiUserInfoAccessSetupAdminGuid;
extern EFI_GUID gEfiUserInfoAccessSetupNormalGuid;
extern EFI_GUID gEfiUserInfoAccessSetupRestrictedGuid;

typedef struct _EFI_USER_CREDENTIAL_PROTOCOL EFI_USER_CREDENTIAL_PROTOCOL;
typedef
EFI_STATUS
( *EFI_CREDENTIAL_ENROLL)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_FORM)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_HII_HANDLE *Hii,
EFI_GUID *FormSetId,
EFI_FORM_ID *FormId
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_TILE)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
UINTN *Width,
UINTN *Height,
EFI_HII_HANDLE *Hii,
EFI_IMAGE_ID *Image
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_TITLE)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_HII_HANDLE *Hii,
EFI_STRING_ID *String
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_USER)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_IDENTIFIER *Identifier
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_SELECT)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_DESELECT)(
EFI_USER_CREDENTIAL_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_DEFAULT)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_GET_INFO)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_USER_INFO_HANDLE UserInfo,
EFI_USER_INFO *Info,
UINTN *InfoSize
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL_GET_NEXT_INFO)(
EFI_USER_CREDENTIAL_PROTOCOL *This,
EFI_USER_INFO_HANDLE *UserInfo
);

struct _EFI_USER_CREDENTIAL_PROTOCOL {
EFI_GUID Identifier;
EFI_GUID Type;
EFI_CREDENTIAL_ENROLL Enroll;
EFI_CREDENTIAL_FORM Form;
EFI_CREDENTIAL_TILE Tile;
EFI_CREDENTIAL_TITLE Title;
EFI_CREDENTIAL_USER User;
EFI_CREDENTIAL_SELECT Select;
EFI_CREDENTIAL_DESELECT Deselect;
EFI_CREDENTIAL_DEFAULT Default;
EFI_CREDENTIAL_GET_INFO GetInfo;
EFI_CREDENTIAL_GET_NEXT_INFO GetNextInfo;
EFI_CREDENTIAL_CAPABILITIES Capabilities;
};

extern EFI_GUID gEfiUserCredentialProtocolGuid;
typedef struct _EFI_USER_CREDENTIAL2_PROTOCOL EFI_USER_CREDENTIAL2_PROTOCOL;
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_ENROLL)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_FORM)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_HII_HANDLE *Hii,
EFI_GUID *FormSetId,
EFI_FORM_ID *FormId
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_TILE)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
UINTN *Width,
UINTN *Height,
EFI_HII_HANDLE *Hii,
EFI_IMAGE_ID *Image
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_TITLE)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_HII_HANDLE *Hii,
EFI_STRING_ID *String
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_USER)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User,
EFI_USER_INFO_IDENTIFIER *Identifier
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_SELECT)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_DESELECT)(
EFI_USER_CREDENTIAL2_PROTOCOL *This
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_DEFAULT)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_GET_INFO)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_USER_INFO_HANDLE UserInfo,
EFI_USER_INFO *Info,
UINTN *InfoSize
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_GET_NEXT_INFO)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_USER_INFO_HANDLE *UserInfo
);
typedef
EFI_STATUS
( *EFI_CREDENTIAL2_DELETE)(
EFI_USER_CREDENTIAL2_PROTOCOL *This,
EFI_USER_PROFILE_HANDLE User
);

struct _EFI_USER_CREDENTIAL2_PROTOCOL {
EFI_GUID Identifier;
EFI_GUID Type;
EFI_CREDENTIAL2_ENROLL Enroll;
EFI_CREDENTIAL2_FORM Form;
EFI_CREDENTIAL2_TILE Tile;
EFI_CREDENTIAL2_TITLE Title;
EFI_CREDENTIAL2_USER User;
EFI_CREDENTIAL2_SELECT Select;
EFI_CREDENTIAL2_DESELECT Deselect;
EFI_CREDENTIAL2_DEFAULT Default;
EFI_CREDENTIAL2_GET_INFO GetInfo;
EFI_CREDENTIAL2_GET_NEXT_INFO GetNextInfo;
EFI_CREDENTIAL_CAPABILITIES Capabilities;
EFI_CREDENTIAL2_DELETE Delete;
};

extern EFI_GUID gEfiUserCredential2ProtocolGuid;

extern EFI_GUID gEfiVariableArchProtocolGuid;
extern EFI_GUID gEfiVariableWriteArchProtocolGuid;
typedef struct _EFI_VLAN_CONFIG_PROTOCOL EFI_VLAN_CONFIG_PROTOCOL;

typedef struct {
UINT16 VlanId;
UINT8 Priority;
} EFI_VLAN_FIND_DATA;
typedef
EFI_STATUS
( *EFI_VLAN_CONFIG_SET)(
EFI_VLAN_CONFIG_PROTOCOL *This,
UINT16 VlanId,
UINT8 Priority
);
typedef
EFI_STATUS
( *EFI_VLAN_CONFIG_FIND)(
EFI_VLAN_CONFIG_PROTOCOL *This,
UINT16 *VlanId ,
UINT16 *NumberOfVlan,
EFI_VLAN_FIND_DATA **Entries
);
typedef
EFI_STATUS
( *EFI_VLAN_CONFIG_REMOVE)(
EFI_VLAN_CONFIG_PROTOCOL *This,
UINT16 VlanId
);

struct _EFI_VLAN_CONFIG_PROTOCOL {
EFI_VLAN_CONFIG_SET Set;
EFI_VLAN_CONFIG_FIND Find;
EFI_VLAN_CONFIG_REMOVE Remove;
};

extern EFI_GUID gEfiVlanConfigProtocolGuid;
typedef struct _EFI_WATCHDOG_TIMER_ARCH_PROTOCOL EFI_WATCHDOG_TIMER_ARCH_PROTOCOL;
typedef
void
( *EFI_WATCHDOG_TIMER_NOTIFY)(
UINT64 Time
);
typedef
EFI_STATUS
( *EFI_WATCHDOG_TIMER_REGISTER_HANDLER)(
EFI_WATCHDOG_TIMER_ARCH_PROTOCOL *This,
EFI_WATCHDOG_TIMER_NOTIFY NotifyFunction
);
typedef
EFI_STATUS
( *EFI_WATCHDOG_TIMER_SET_TIMER_PERIOD)(
EFI_WATCHDOG_TIMER_ARCH_PROTOCOL *This,
UINT64 TimerPeriod
);
typedef
EFI_STATUS
( *EFI_WATCHDOG_TIMER_GET_TIMER_PERIOD)(
EFI_WATCHDOG_TIMER_ARCH_PROTOCOL *This,
UINT64 *TimerPeriod
);
struct _EFI_WATCHDOG_TIMER_ARCH_PROTOCOL {
EFI_WATCHDOG_TIMER_REGISTER_HANDLER RegisterHandler;
EFI_WATCHDOG_TIMER_SET_TIMER_PERIOD SetTimerPeriod;
EFI_WATCHDOG_TIMER_GET_TIMER_PERIOD GetTimerPeriod;
};

extern EFI_GUID gEfiWatchdogTimerArchProtocolGuid;

//XenoAdded from FirmwareVolume.h
typedef UINT32  EFI_FV_FILE_ATTRIBUTES;
typedef void  * EFI_PEI_FILE_HANDLE;
typedef void  * EFI_PEI_FV_HANDLE;
typedef UINT32  EFI_FVB_ATTRIBUTES;

typedef struct {
  EFI_GUID                FileName;
  EFI_FV_FILETYPE         FileType;
  EFI_FV_FILE_ATTRIBUTES  FileAttributes;
  void                    *Buffer;
  UINT32                  BufferSize;
} EFI_FV_FILE_INFO;

typedef struct {
  EFI_FVB_ATTRIBUTES  FvAttributes;
  EFI_GUID            FvFormat;
  EFI_GUID            FvName;
  void                *FvStart;
  UINT64              FvSize;
} EFI_FV_INFO;

//XenoAdded from PeiApi.h

//hack cause I can't use EFI_FORWARD_DECLARATION()
typedef void * PEFI_PEI_SERVICES;

//
// PEI Ppi Services List Descriptors
//
#define EFI_PEI_PPI_DESCRIPTOR_PIC              0x00000001
#define EFI_PEI_PPI_DESCRIPTOR_PPI              0x00000010
#define EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK  0x00000020
#define EFI_PEI_PPI_DESCRIPTOR_NOTIFY_DISPATCH  0x00000040
#define EFI_PEI_PPI_DESCRIPTOR_NOTIFY_TYPES     0x00000060
#define EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST   0x80000000

typedef struct {
  UINTN     Flags;
  EFI_GUID  *Guid;
  void      *Ppi;
} EFI_PEI_PPI_DESCRIPTOR;

//hack cause I can't use EFI_FORWARD_DECLARATION()
typedef void * EFI_PEIM_NOTIFY_ENTRY_POINT;

typedef struct {
  UINTN                       Flags;
  EFI_GUID                    *Guid;
  EFI_PEIM_NOTIFY_ENTRY_POINT Notify;
} EFI_PEI_NOTIFY_DESCRIPTOR;

//
// PEI PPI Services
//
typedef
EFI_STATUS
( *EFI_PEI_INSTALL_PPI) (
PEFI_PEI_SERVICES            *PeiServices,
EFI_PEI_PPI_DESCRIPTOR      * PpiList
  );

typedef
EFI_STATUS
( *EFI_PEI_REINSTALL_PPI) (
PEFI_PEI_SERVICES                *PeiServices,
EFI_PEI_PPI_DESCRIPTOR          * OldPpi,
EFI_PEI_PPI_DESCRIPTOR          * NewPpi
  );

typedef
EFI_STATUS
( *EFI_PEI_LOCATE_PPI) (
PEFI_PEI_SERVICES            *PeiServices,
EFI_GUID                    * Guid,
UINTN                             Instance,
EFI_PEI_PPI_DESCRIPTOR        **PpiDescriptor,
void                          **Ppi
  );

typedef
EFI_STATUS
( *EFI_PEI_NOTIFY_PPI) (
PEFI_PEI_SERVICES                *PeiServices,
EFI_PEI_NOTIFY_DESCRIPTOR       * NotifyList
  );

//
// PEI Boot Mode Services
//
typedef
EFI_STATUS
( *EFI_PEI_GET_BOOT_MODE) (
PEFI_PEI_SERVICES            *PeiServices,
EFI_BOOT_MODE                 * BootMode
  );

typedef
EFI_STATUS
( *EFI_PEI_SET_BOOT_MODE) (
PEFI_PEI_SERVICES            *PeiServices,
EFI_BOOT_MODE                     BootMode
  );

//
// PEI HOB Services
//
typedef
EFI_STATUS
( *EFI_PEI_GET_HOB_LIST) (
PEFI_PEI_SERVICES            *PeiServices,
void                          **HobList
  );

typedef
EFI_STATUS
( *EFI_PEI_CREATE_HOB) (
PEFI_PEI_SERVICES            *PeiServices,
UINT16                            Type,
UINT16                            Length,
void                          **Hob
  );



 //
 // PEI Firmware Volume Services
 //
typedef
EFI_STATUS
( *EFI_PEI_FFS_FIND_NEXT_VOLUME2) (
PEFI_PEI_SERVICES  *PeiServices,
UINTN                    Instance,
EFI_PEI_FV_HANDLE    *VolumeHandle 
  );

typedef
EFI_STATUS
( *EFI_PEI_FFS_FIND_NEXT_FILE2) (
PEFI_PEI_SERVICES        *PeiServices,
EFI_FV_FILETYPE                SearchType,
EFI_PEI_FV_HANDLE        FvHandle,
EFI_PEI_FILE_HANDLE        *FileHandle  
  );

typedef
EFI_STATUS
( *EFI_PEI_FFS_FIND_SECTION_DATA2) (
PEFI_PEI_SERVICES    *PeiServices,
EFI_SECTION_TYPE           SectionType,
EFI_PEI_FILE_HANDLE        FileHandle,
  void                      **SectionData
  );

  
  //
  // PEI Memory Services
  //
typedef
EFI_STATUS
( *EFI_PEI_INSTALL_PEI_MEMORY) (
PEFI_PEI_SERVICES     *PeiServices,
EFI_PHYSICAL_ADDRESS       MemoryBegin,
UINT64                     MemoryLength
  );

typedef
EFI_STATUS
( *EFI_PEI_ALLOCATE_PAGES) (

PEFI_PEI_SERVICES     *PeiServices,
EFI_MEMORY_TYPE            MemoryType,
UINTN                      Pages,
EFI_PHYSICAL_ADDRESS   * Memory
  );

typedef
EFI_STATUS
( *EFI_PEI_ALLOCATE_POOL) (
PEFI_PEI_SERVICES          *PeiServices,
UINTN                           Size,
  void                           **Buffer
  );

typedef
void
( *EFI_PEI_COPY_MEM) (
void                       *Destination,
void                       *Source,
UINTN                      Length
  );

typedef
void
( *EFI_PEI_SET_MEM) (
void                       *Buffer,
UINTN                      Size,
UINT8                      Value
  );

  //
  // New interfaceas added by the PI 1.0
  //
typedef 
EFI_STATUS
( *EFI_PEI_FFS_FIND_BY_NAME) (
 const EFI_GUID        *FileName,
 EFI_PEI_FV_HANDLE     VolumeHandle,
  EFI_PEI_FILE_HANDLE   *FileHandle
  );


typedef
EFI_STATUS
( *EFI_PEI_FFS_GET_FILE_INFO) (
 EFI_PEI_FILE_HANDLE   FileHandle,
  EFI_FV_FILE_INFO      *FileInfo
  );


typedef
EFI_STATUS
( *EFI_PEI_FFS_GET_VOLUME_INFO) (
 EFI_PEI_FV_HANDLE     VolumeHandle,
  EFI_FV_INFO           *VolumeInfo
  );

typedef
EFI_STATUS
( *EFI_PEI_REGISTER_FOR_SHADOW) (
EFI_PEI_FILE_HANDLE       FileHandle
  );

//
// PEI Status Code Service
//
typedef
EFI_STATUS
( *EFI_PEI_REPORT_STATUS_CODE) (
PEFI_PEI_SERVICES               *PeiServices,
EFI_STATUS_CODE_TYPE           Type,
EFI_STATUS_CODE_VALUE          Value,
UINT32                         Instance,
EFI_GUID                       *CallerId,
EFI_STATUS_CODE_DATA           *Data
  );

//
// PEI Reset Service
//
typedef
EFI_STATUS
( *EFI_PEI_RESET_SYSTEM) (
PEFI_PEI_SERVICES   *PeiServices
  );

//
// EFI PEI Services Table
//

//Again, laziness, I don't want to go get these defs
typedef void * PEI_CPU_IO_PPI_ACCESS;
typedef void * PEI_CPU_IO_PPI_IO_READ8;
typedef void * PEI_CPU_IO_PPI_IO_READ16;
typedef void * PEI_CPU_IO_PPI_IO_READ32;
typedef void * PEI_CPU_IO_PPI_IO_READ64;
typedef void * PEI_CPU_IO_PPI_IO_WRITE8;
typedef void * PEI_CPU_IO_PPI_IO_WRITE16;
typedef void * PEI_CPU_IO_PPI_IO_WRITE32;
typedef void * PEI_CPU_IO_PPI_IO_WRITE64;
typedef void * PEI_CPU_IO_PPI_MEM_READ8;
typedef void * PEI_CPU_IO_PPI_MEM_READ16;
typedef void * PEI_CPU_IO_PPI_MEM_READ32;
typedef void * PEI_CPU_IO_PPI_MEM_READ64;
typedef void * PEI_CPU_IO_PPI_MEM_WRITE8;
typedef void * PEI_CPU_IO_PPI_MEM_WRITE16;
typedef void * PEI_CPU_IO_PPI_MEM_WRITE32;
typedef void * PEI_CPU_IO_PPI_MEM_WRITE64;

typedef struct _PEI_CPU_IO_PPI {
  PEI_CPU_IO_PPI_ACCESS       Mem;
  PEI_CPU_IO_PPI_ACCESS       Io;
  PEI_CPU_IO_PPI_IO_READ8     IoRead8;
  PEI_CPU_IO_PPI_IO_READ16    IoRead16;
  PEI_CPU_IO_PPI_IO_READ32    IoRead32;
  PEI_CPU_IO_PPI_IO_READ64    IoRead64;
  PEI_CPU_IO_PPI_IO_WRITE8    IoWrite8;
  PEI_CPU_IO_PPI_IO_WRITE16   IoWrite16;
  PEI_CPU_IO_PPI_IO_WRITE32   IoWrite32;
  PEI_CPU_IO_PPI_IO_WRITE64   IoWrite64;
  PEI_CPU_IO_PPI_MEM_READ8    MemRead8;
  PEI_CPU_IO_PPI_MEM_READ16   MemRead16;
  PEI_CPU_IO_PPI_MEM_READ32   MemRead32;
  PEI_CPU_IO_PPI_MEM_READ64   MemRead64;
  PEI_CPU_IO_PPI_MEM_WRITE8   MemWrite8;
  PEI_CPU_IO_PPI_MEM_WRITE16  MemWrite16;
  PEI_CPU_IO_PPI_MEM_WRITE32  MemWrite32;
  PEI_CPU_IO_PPI_MEM_WRITE64  MemWrite64;
} PEI_CPU_IO_PPI;

typedef PEI_CPU_IO_PPI          EFI_PEI_CPU_IO_PPI;

//Again, laziness, I don't want to go get these defs
typedef void * EFI_PEI_PCI_CFG_PPI_IO;
typedef void * EFI_PEI_PCI_CFG_PPI_RW;

typedef struct _EFI_PEI_PCI_CFG2_PPI {
  EFI_PEI_PCI_CFG_PPI_IO  Read;
  EFI_PEI_PCI_CFG_PPI_IO  Write;
  EFI_PEI_PCI_CFG_PPI_RW  Modify;
  UINT16                  Segment;
} EFI_PEI_PCI_CFG2_PPI;

// Most members of struct _EFI_PEI_SERVICES are Fn Ptrs
typedef void* EFI_PEI_INSTALL_PPI;
typedef void* EFI_PEI_REINSTALL_PPI;
typedef void* EFI_PEI_LOCATE_PPI;
typedef void* EFI_PEI_NOTIFY_PPI;
typedef void* EFI_PEI_GET_BOOT_MODE;
typedef void* EFI_PEI_SET_BOOT_MODE;
typedef void* EFI_PEI_GET_HOB_LIST;
typedef void* EFI_PEI_CREATE_HOB;
typedef void* EFI_PEI_FFS_FIND_NEXT_VOLUME2;
typedef void* EFI_PEI_FFS_FIND_NEXT_FILE2;
typedef void* EFI_PEI_FFS_FIND_SECTION_DATA2;
typedef void* EFI_PEI_INSTALL_PEI_MEMORY;
typedef void* EFI_PEI_ALLOCATE_PAGES;
typedef void* EFI_PEI_ALLOCATE_POOL;
typedef void* EFI_PEI_COPY_MEM;
typedef void* EFI_PEI_SET_MEM;
typedef void* EFI_PEI_REPORT_STATUS_CODE;
typedef void* EFI_PEI_RESET_SYSTEM;
typedef void* EFI_PEI_CPU_IO_PPI;
typedef void* EFI_PEI_PCI_CFG2_PPI;
typedef void* EFI_PEI_FFS_FIND_BY_NAME;
typedef void* EFI_PEI_FFS_GET_FILE_INFO;
typedef void* EFI_PEI_FFS_GET_VOLUME_INFO;
typedef void* EFI_PEI_REGISTER_FOR_SHADOW;

typedef struct _EFI_PEI_SERVICES {
  EFI_TABLE_HEADER              Hdr;

  //
  // PPI Functions
  //
  EFI_PEI_INSTALL_PPI           InstallPpi;
  EFI_PEI_REINSTALL_PPI         ReInstallPpi;
  EFI_PEI_LOCATE_PPI            LocatePpi;
  EFI_PEI_NOTIFY_PPI            NotifyPpi;

  //
  // Boot Mode Functions
  //
  EFI_PEI_GET_BOOT_MODE         GetBootMode;
  EFI_PEI_SET_BOOT_MODE         SetBootMode;

  //
  // HOB Functions
  //
  EFI_PEI_GET_HOB_LIST          GetHobList;
  EFI_PEI_CREATE_HOB            CreateHob;

  //
  // Firmware Volume Functions
  //
  EFI_PEI_FFS_FIND_NEXT_VOLUME2  FfsFindNextVolume;
  EFI_PEI_FFS_FIND_NEXT_FILE2    FfsFindNextFile;
  EFI_PEI_FFS_FIND_SECTION_DATA2 FfsFindSectionData;
  //
  // PEI Memory Functions
  //
  EFI_PEI_INSTALL_PEI_MEMORY    InstallPeiMemory;
  EFI_PEI_ALLOCATE_PAGES        AllocatePages;
  EFI_PEI_ALLOCATE_POOL         AllocatePool;
  EFI_PEI_COPY_MEM              CopyMem;
  EFI_PEI_SET_MEM               SetMem;

  //
  // Status Code
  //
  EFI_PEI_REPORT_STATUS_CODE    PeiReportStatusCode;

  //
  // Reset
  //
  EFI_PEI_RESET_SYSTEM          PeiResetSystem;

  //
  // Pointer to PPI interface
  //
  EFI_PEI_CPU_IO_PPI             *CpuIo;
  EFI_PEI_PCI_CFG2_PPI           *PciCfg;

  //
  // New interfaceas added by the PI 1.0
  //
  EFI_PEI_FFS_FIND_BY_NAME        FfsFindFileByName;
  EFI_PEI_FFS_GET_FILE_INFO       FfsGetFileInfo;
  EFI_PEI_FFS_GET_VOLUME_INFO     FfsGetVolumeInfo;
  EFI_PEI_REGISTER_FOR_SHADOW     RegisterForShadow;
} EFI_PEI_SERVICES;

//
// JB: Some PEI structures
//
#pragma pack(8)   // n = 8
typedef struct _EFI_PEI_FIRMWARE_VOLUME_PPI {
  void* ProcessVolume; // EFI_PEI_FV_PROCESS_FV
  void* FindFileByType; //EFI_PEI_FV_FIND_FILE_TYPE
  void* FindFileByName;//EFI_PEI_FV_FIND_FILE_NAME
  void* GetFileInfo;//EFI_PEI_FV_GET_FILE_INFO
  void* GetVolumeInfo;//EFI_PEI_FV_GET_INFO
  void* FindSectionByType;//EFI_PEI_FV_FIND_SECTION
} EFI_PEI_FIRMWARE_VOLUME_PPI;
//typedef struct _EFI_PEI_FIRMWARE_VOLUME_PPI   EFI_PEI_FIRMWARE_VOLUME_PPI;

typedef union {
  EFI_PEI_PPI_DESCRIPTOR      *Ppi;
  EFI_PEI_NOTIFY_DESCRIPTOR   *Notify;
  void                        *Raw;
} PEI_PPI_LIST_POINTERS;

typedef struct {
  INTN                    PpiListEnd;
  INTN                    NotifyListEnd;
  INTN                    DispatchListEnd;
  INTN                    LastDispatchedInstall;
  INTN                    LastDispatchedNotify;
  PEI_PPI_LIST_POINTERS   PpiListPtrs[64]; // 64 from debugger
} PEI_PPI_DATABASE;

typedef struct _PEI_CORE_FV_HANDLE {
  EFI_FIRMWARE_VOLUME_HEADER          *FvHeader;
  EFI_PEI_FIRMWARE_VOLUME_PPI         *FvPpi;
  EFI_PEI_FV_HANDLE                   FvHandle;
  UINT8                               PeimState[32]; // 10 was FixedPcdGet32 (PcdPeiCoreMaxPeimPerFv) - FIX
  EFI_PEI_FILE_HANDLE                 FvFileHandles[32]; // 10 was FixedPcdGet32 (PcdPeiCoreMaxPeimPerFv) - FIX
  BOOLEAN                             ScanFv;
  //FILLER                              AlignMe[3];  // to line it up right in IDA
} PEI_CORE_FV_HANDLE;

typedef struct {
  EFI_GUID                            FvFormat;
  void                                *FvInfo;
  UINT32                              FvInfoSize;
  EFI_PEI_NOTIFY_DESCRIPTOR           NotifyDescriptor;
} PEI_CORE_UNKNOW_FORMAT_FV_INFO;

#define CACHE_SETION_MAX_NUMBER       0x10
typedef struct {
  EFI_COMMON_SECTION_HEADER*          Section[CACHE_SETION_MAX_NUMBER];
  void*                               SectionData[CACHE_SETION_MAX_NUMBER];
  UINTN                               SectionSize[CACHE_SETION_MAX_NUMBER];
  UINTN                               AllSectionCount;
  UINTN                               SectionIndex;
} CACHE_SECTION_DATA;

typedef void*      PEI_SECURITY_AUTHENTICATION_STATE;    // Fn Ptr
typedef PEI_SECURITY_AUTHENTICATION_STATE       EFI_PEI_SECURITY_AUTHENTICATION_STATE;

typedef struct _EFI_PEI_SECURITY2_PPI{
  EFI_PEI_SECURITY_AUTHENTICATION_STATE   AuthenticationState;
} EFI_PEI_SECURITY2_PPI;
//typedef struct _EFI_PEI_SECURITY2_PPI  EFI_PEI_SECURITY2_PPI;

typedef struct _PEI_CORE_INSTANCE {
  UINTN                              Signature;
  EFI_PEI_SERVICES                   *Ps;
  PEI_PPI_DATABASE                   PpiData; 
  UINTN                              FvCount;
  PEI_CORE_FV_HANDLE                 Fv[6]; // 6 taken from Debugger, was PcdPeiCoreMaxFvSupported)
  PEI_CORE_UNKNOW_FORMAT_FV_INFO     UnknownFvInfo[6]; // was FixedPcdGet32 (PcdPeiCoreMaxFvSupported)
  UINTN                              UnknownFvInfoCount;
  EFI_PEI_FILE_HANDLE                CurrentFvFileHandles[32]; // was FixedPcdGet32 (PcdPeiCoreMaxPeimPerFv)
  UINTN                              AprioriCount;
  UINTN                              CurrentPeimFvCount;
  UINTN                              CurrentPeimCount;
  EFI_PEI_FILE_HANDLE                CurrentFileHandle;
  BOOLEAN                            PeimNeedingDispatch;
  BOOLEAN                            PeimDispatchOnThisPass;
  BOOLEAN                            PeimDispatcherReenter;
  //FILLER                             AlignMe1[1];
  EFI_PEI_HOB_POINTERS               HobList;
  BOOLEAN                            SwitchStackSignal;
  BOOLEAN                            PeiMemoryInstalled;
  //FILLER                             AlignMe2[2];
  void                               *CpuIo;
  EFI_PEI_SECURITY2_PPI              *PrivateSecurityPpi; 
  EFI_PEI_SERVICES                   ServiceTableShadow;
  EFI_PEI_PPI_DESCRIPTOR             *XipLoadFile;
  //FILLER                             AlignMe3[4];
  EFI_PHYSICAL_ADDRESS               PhysicalMemoryBegin;
  UINT64                             PhysicalMemoryLength;
  EFI_PHYSICAL_ADDRESS               FreePhysicalMemoryTop;
  UINTN                              HeapOffset;
  BOOLEAN                            HeapOffsetPositive;
  //FILLER                             AlignMe4[3];
  UINTN                              StackOffset;
  BOOLEAN                            StackOffsetPositive;
  //FILLER                             AlignMe5[3];
  UINT32                             ShadowedPeiCore; // actual type: PEICORE_FUNCTION_POINTER
  CACHE_SECTION_DATA                 CacheSection;
  //FILLER                             AlignMe6[4];
  EFI_PHYSICAL_ADDRESS               LoadModuleAtFixAddressTopAddress;
  UINT64                            *PeiCodeMemoryRangeUsageBitMap;
  void                              *ShadowedImageRead;// actual type: PE_COFF_LOADER_READ_FILE
} PEI_CORE_INSTANCE;
//typedef struct _PEI_CORE_INSTANCE  PEI_CORE_INSTANCE;

typedef void *        EFI_DXE_IPL_ENTRY;   // FIX

struct _EFI_DXE_IPL_PPI {
  EFI_DXE_IPL_ENTRY Entry;
};
typedef struct _EFI_DXE_IPL_PPI EFI_DXE_IPL_PPI;

typedef union {
  UINT32                        PeiCore;  // actual type: PEICORE_FUNCTION_POINTER
  void                         *PeimEntry; // actual type EFI_PEIM_ENTRY_POINT2
  EFI_PEIM_NOTIFY_ENTRY_POINT  PeimNotifyEntry;
  EFI_DXE_IPL_PPI              *DxeIpl;
  EFI_PEI_PPI_DESCRIPTOR       *PpiDescriptor;
  EFI_PEI_NOTIFY_DESCRIPTOR    *NotifyDescriptor;
  void                         *Raw;
} PEI_CORE_TEMP_POINTERS;



/*
EFI_PCD_PROTOCOL

A platform database that contains a variety of current platform settings or directives that can be
accessed by a driver or application. 
*/
typedef struct _EFI_PCD_PROTOCOL {
  PVOID              SetSku;
  PVOID                Get8;
  PVOID               Get16;
  PVOID               Get32;
  PVOID               Get64;
  PVOID          GetPtr;
  PVOID          GetBool;
  PVOID             GetSize;
  PVOID                Set8;
  PVOID               Set16;
  PVOID               Set32;
  PVOID               Set64;
  PVOID          SetPtr;
  PVOID          SetBool;
  PVOID      CallbackOnSet;
  PVOID      CancelCallback;
  PVOID       GetNextToken;
  PVOID GetNextTokenSpace;
} EFI_PCD_PROTOCOL;

typedef struct _EFI_MM_BASE_PROTOCOL {
  PVOID         InMm;
  PVOID  GetMmstLocation;
} EFI_MM_BASE_PROTOCOL;

typedef struct _EFI_SMM_VARIABLE_PROTOCOL {
  PVOID            SmmGetVariable;
  PVOID  SmmGetNextVariableName;
  PVOID            SmmSetVariable;
  PVOID     SmmQueryVariableInfo;
} EFI_SMM_VARIABLE_PROTOCOL;



/*
Register a child MMI source dispatch function for the specified software MMI.

  This service registers a function (DispatchFunction) which will be called when the software
  MMI source specified by RegisterContext->SwMmiCpuIndex is detected.
*/

typedef struct {
  UINTN SwMmiInputValue;
} EFI_MM_SW_REGISTER_CONTEXT;


/*typedef
EFI_STATUS
(EFIAPI *EFI_MM_SW_REGISTER)(
  PVOID  This,
  PVOID   DispatchFunction,
  EFI_MM_SW_REGISTER_CONTEXT   *RegisterContext,
  EFI_HANDLE                   *DispatchHandle
  );
*/

/// Interface structure for the MM Software MMI Dispatch Protocol.
///
/// The EFI_MM_SW_DISPATCH_PROTOCOL provides the ability to install child handlers for the
/// given software.  These handlers will respond to software interrupts, and the maximum software
/// interrupt in the EFI_MM_SW_REGISTER_CONTEXT is denoted by MaximumSwiValue.
///
typedef struct _EFI_MM_SW_DISPATCH_PROTOCOL {
  PVOID    Register;
  PVOID  UnRegister;
  ///
  /// A read-only field that describes the maximum value that can be used in the
  /// EFI_MM_SW_DISPATCH_PROTOCOL.Register() service.
  ///
  UINTN                 MaximumSwiValue;
} EFI_MM_SW_DISPATCH_PROTOCOL;


typedef
EFI_STATUS
(EFIAPI *EFI_FV_READ_SECTION)(
  IN CONST  EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
  IN CONST  EFI_GUID                      *NameGuid,
  IN        EFI_SECTION_TYPE              SectionType,
  IN        UINTN                         SectionInstance,
  IN OUT    VOID                          **Buffer,
  IN OUT    UINTN                         *BufferSize,
  OUT       UINT32                        *AuthenticationStatus
  );

typedef struct _EFI_FIRMWARE_VOLUME2_PROTOCOL {
  PVOID    GetVolumeAttributes;
  PVOID    SetVolumeAttributes;
  PVOID         ReadFile;
  EFI_FV_READ_SECTION ReadSection; // ReadSection() is used to retrieve a specific section from a file within a firmware volume.
  PVOID        WriteFile;
  PVOID     GetNextFile;
  UINT32                   KeySize;
  EFI_HANDLE               ParentHandle;
  PVOID          GetInfo;
  PVOID          SetInfo;
} EFI_FIRMWARE_VOLUME2_PROTOCOL;


///
/// Can be used on any image handle to obtain information about the loaded image.
///
typedef struct {
  UINT32            Revision;       ///< Defines the revision of the EFI_LOADED_IMAGE_PROTOCOL structure. 
                                    ///< All future revisions will be backward compatible to the current revision.
  EFI_HANDLE        ParentHandle;   ///< Parent image's image handle. NULL if the image is loaded directly from 
                                    ///< the firmware's boot manager. 
  EFI_SYSTEM_TABLE  *SystemTable;   ///< the image's EFI system table pointer.

  //
  // Source location of image
  //
  EFI_HANDLE        DeviceHandle;   ///< The device handle that the EFI Image was loaded from. 
  EFI_DEVICE_PATH_PROTOCOL  *FilePath;  ///< A pointer to the file path portion specific to DeviceHandle 
                                        ///< that the EFI Image was loaded from. 
  PVOID Reserved;      ///< Reserved. DO NOT USE.

  //
  // Images load options
  //
  UINT32            LoadOptionsSize;///< The size in bytes of LoadOptions.
  PVOID LoadOptions;   ///< A pointer to the image's binary load options.

  //
  // Location of where image was loaded
  //
  PVOID ImageBase;     ///< The base address at which the image was loaded.
  UINT64            ImageSize;      ///< The size in bytes of the loaded image.
  EFI_MEMORY_TYPE   ImageCodeType;  ///< The memory type that the code sections were loaded as.
  EFI_MEMORY_TYPE   ImageDataType;  ///< The memory type that the data sections were loaded as.
  EFI_IMAGE_UNLOAD  Unload;
} EFI_LOADED_IMAGE_PROTOCOL;


typedef enum {
  ///
  /// x86/X64 standard registers
  ///
  EFI_MM_SAVE_STATE_REGISTER_GDTBASE       = 4,
  EFI_MM_SAVE_STATE_REGISTER_IDTBASE       = 5,
  EFI_MM_SAVE_STATE_REGISTER_LDTBASE       = 6,
  EFI_MM_SAVE_STATE_REGISTER_GDTLIMIT      = 7,
  EFI_MM_SAVE_STATE_REGISTER_IDTLIMIT      = 8,
  EFI_MM_SAVE_STATE_REGISTER_LDTLIMIT      = 9,
  EFI_MM_SAVE_STATE_REGISTER_LDTINFO       = 10,
  EFI_MM_SAVE_STATE_REGISTER_ES            = 20,
  EFI_MM_SAVE_STATE_REGISTER_CS            = 21,
  EFI_MM_SAVE_STATE_REGISTER_SS            = 22,
  EFI_MM_SAVE_STATE_REGISTER_DS            = 23,
  EFI_MM_SAVE_STATE_REGISTER_FS            = 24,
  EFI_MM_SAVE_STATE_REGISTER_GS            = 25,
  EFI_MM_SAVE_STATE_REGISTER_LDTR_SEL      = 26,
  EFI_MM_SAVE_STATE_REGISTER_TR_SEL        = 27,
  EFI_MM_SAVE_STATE_REGISTER_DR7           = 28,
  EFI_MM_SAVE_STATE_REGISTER_DR6           = 29,
  EFI_MM_SAVE_STATE_REGISTER_R8            = 30,
  EFI_MM_SAVE_STATE_REGISTER_R9            = 31,
  EFI_MM_SAVE_STATE_REGISTER_R10           = 32,
  EFI_MM_SAVE_STATE_REGISTER_R11           = 33,
  EFI_MM_SAVE_STATE_REGISTER_R12           = 34,
  EFI_MM_SAVE_STATE_REGISTER_R13           = 35,
  EFI_MM_SAVE_STATE_REGISTER_R14           = 36,
  EFI_MM_SAVE_STATE_REGISTER_R15           = 37,
  EFI_MM_SAVE_STATE_REGISTER_RAX           = 38,
  EFI_MM_SAVE_STATE_REGISTER_RBX           = 39,
  EFI_MM_SAVE_STATE_REGISTER_RCX           = 40,
  EFI_MM_SAVE_STATE_REGISTER_RDX           = 41,
  EFI_MM_SAVE_STATE_REGISTER_RSP           = 42,
  EFI_MM_SAVE_STATE_REGISTER_RBP           = 43,
  EFI_MM_SAVE_STATE_REGISTER_RSI           = 44,
  EFI_MM_SAVE_STATE_REGISTER_RDI           = 45,
  EFI_MM_SAVE_STATE_REGISTER_RIP           = 46,
  EFI_MM_SAVE_STATE_REGISTER_RFLAGS        = 51,
  EFI_MM_SAVE_STATE_REGISTER_CR0           = 52,
  EFI_MM_SAVE_STATE_REGISTER_CR3           = 53,
  EFI_MM_SAVE_STATE_REGISTER_CR4           = 54,
  EFI_MM_SAVE_STATE_REGISTER_FCW           = 256,
  EFI_MM_SAVE_STATE_REGISTER_FSW           = 257,
  EFI_MM_SAVE_STATE_REGISTER_FTW           = 258,
  EFI_MM_SAVE_STATE_REGISTER_OPCODE        = 259,
  EFI_MM_SAVE_STATE_REGISTER_FP_EIP        = 260,
  EFI_MM_SAVE_STATE_REGISTER_FP_CS         = 261,
  EFI_MM_SAVE_STATE_REGISTER_DATAOFFSET    = 262,
  EFI_MM_SAVE_STATE_REGISTER_FP_DS         = 263,
  EFI_MM_SAVE_STATE_REGISTER_MM0           = 264,
  EFI_MM_SAVE_STATE_REGISTER_MM1           = 265,
  EFI_MM_SAVE_STATE_REGISTER_MM2           = 266,
  EFI_MM_SAVE_STATE_REGISTER_MM3           = 267,
  EFI_MM_SAVE_STATE_REGISTER_MM4           = 268,
  EFI_MM_SAVE_STATE_REGISTER_MM5           = 269,
  EFI_MM_SAVE_STATE_REGISTER_MM6           = 270,
  EFI_MM_SAVE_STATE_REGISTER_MM7           = 271,
  EFI_MM_SAVE_STATE_REGISTER_XMM0          = 272,
  EFI_MM_SAVE_STATE_REGISTER_XMM1          = 273,
  EFI_MM_SAVE_STATE_REGISTER_XMM2          = 274,
  EFI_MM_SAVE_STATE_REGISTER_XMM3          = 275,
  EFI_MM_SAVE_STATE_REGISTER_XMM4          = 276,
  EFI_MM_SAVE_STATE_REGISTER_XMM5          = 277,
  EFI_MM_SAVE_STATE_REGISTER_XMM6          = 278,
  EFI_MM_SAVE_STATE_REGISTER_XMM7          = 279,
  EFI_MM_SAVE_STATE_REGISTER_XMM8          = 280,
  EFI_MM_SAVE_STATE_REGISTER_XMM9          = 281,
  EFI_MM_SAVE_STATE_REGISTER_XMM10         = 282,
  EFI_MM_SAVE_STATE_REGISTER_XMM11         = 283,
  EFI_MM_SAVE_STATE_REGISTER_XMM12         = 284,
  EFI_MM_SAVE_STATE_REGISTER_XMM13         = 285,
  EFI_MM_SAVE_STATE_REGISTER_XMM14         = 286,
  EFI_MM_SAVE_STATE_REGISTER_XMM15         = 287,
  ///
  /// Pseudo-Registers
  ///
  EFI_MM_SAVE_STATE_REGISTER_IO            = 512,
  EFI_MM_SAVE_STATE_REGISTER_LMA           = 513,
  EFI_MM_SAVE_STATE_REGISTER_PROCESSOR_ID  = 514
} EFI_MM_SAVE_STATE_REGISTER;

/*
EFI_STATUS
EFIAPI
SmmReadSaveState (
  IN CONST EFI_SMM_CPU_PROTOCOL         *This,
  IN UINTN                              Width,
  IN EFI_SMM_SAVE_STATE_REGISTER        Register,
  IN UINTN                              CpuIndex,
  OUT VOID                              *Buffer
  )
*/

typedef struct _EFI_MM_CPU_PROTOCOL {
  PVOID   ReadSaveState;
  PVOID  WriteSaveState;
} EFI_MM_CPU_PROTOCOL;



/*
RuntimeServices

typedef
EFI_STATUS
(EFIAPI *EFI_SET_VARIABLE)(
  IN CHAR16   *VariableName, 
  IN EFI_GUID *VendorGuid,
  IN UINT32   Attributes,
  IN UINTN    DataSize,
  IN VOID     *Data
  );

*/


///
/// Abstracts the traditional BIOS from the rest of EFI. The LegacyBoot()
/// member function allows the BDS to support booting a traditional OS.
/// EFI thunks drivers that make EFI bindings for BIOS INT services use
/// all the other member functions.
///
typedef struct _EFI_LEGACY_BIOS_PROTOCOL {
  ///
  /// Performs traditional software INT. See the Int86() function description.
  ///
  PVOID                       Int86;
  
  ///
  /// Performs a far call into Compatibility16 or traditional OpROM code.
  ///
  PVOID                   FarCall86;
  
  ///
  /// Checks if a traditional OpROM exists for this device.
  ///
  PVOID                   CheckPciRom;
  
  ///
  /// Loads a traditional OpROM in traditional OpROM address space.
  ///
  PVOID                 InstallPciRom;
  
  ///
  /// Boots a traditional OS.
  ///
  PVOID                        LegacyBoot;
  
  ///
  /// Updates BDA to reflect the current EFI keyboard LED status.
  ///
  PVOID  UpdateKeyboardLedStatus;
  
  ///
  /// Allows an external agent, such as BIOS Setup, to get the BBS data.
  ///
  PVOID                GetBbsInfo;
  
  ///
  /// Causes all legacy OpROMs to be shadowed.
  ///
  PVOID    ShadowAllLegacyOproms;
  
  ///
  /// Performs all actions prior to boot. Used when booting an EFI-aware OS
  /// rather than a legacy OS.  
  ///
  PVOID         PrepareToBootEfi;
  
  ///
  /// Allows EFI to reserve an area in the 0xE0000 or 0xF0000 block.
  ///
  PVOID           GetLegacyRegion;
  
  ///
  /// Allows EFI to copy data to the area specified by GetLegacyRegion.
  ///
  PVOID          CopyLegacyRegion;
  
  ///
  /// Allows the user to boot off an unconventional device such as a PARTIES partition.
  ///
  PVOID  BootUnconventionalDevice;
} EFI_LEGACY_BIOS_PROTOCOL;

typedef struct {
  UINT32                   Signature;
  UINT32                   SwSmiNumber;
  EFI_PHYSICAL_ADDRESS     BufferPtrAddress;
} EFI_SMM_COMMUNICATION_CONTEXT;


typedef struct _EFI_MM_SW_CONTEXT {
  ///
  /// The 0-based index of the CPU which generated the software MMI.
  ///
  UINTN SwMmiCpuIndex;
  ///
  /// This value corresponds directly to the CommandPort parameter used in the call to Trigger().
  ///
  UINT8 CommandPort;
  ///
  /// This value corresponds directly to the DataPort parameter used in the call to Trigger().
  ///
  UINT8 DataPort;
} EFI_MM_SW_CONTEXT;



#define EFI_MM_CPU_IO_PROTOCOL_GUID \
{ \
 0x3242A9D8, 0xCE70, 0x4AA0, { 0x95, 0x5D, 0x5E, 0x7B, 0x14, 0x0D, 0xE4, 0xD2 } \
}

typedef struct _EFI_MM_CPU_IO_PROTOCOL  EFI_MM_CPU_IO_PROTOCOL;

typedef enum {
MM_IO_UINT8  = 0,
MM_IO_UINT16 = 1,
MM_IO_UINT32 = 2,
MM_IO_UINT64 = 3
} EFI_MM_IO_WIDTH;

typedef
EFI_STATUS
(*EFI_MM_CPU_IO)(
EFI_MM_CPU_IO_PROTOCOL	*This,
EFI_MM_IO_WIDTH	Width,
UINT64	Address,
UINTN	Count,
void	*Buffer);

typedef struct {
EFI_MM_CPU_IO  Read;
EFI_MM_CPU_IO  Write;
} EFI_MM_IO_ACCESS;

struct _EFI_MM_CPU_IO_PROTOCOL {
EFI_MM_IO_ACCESS Mem;
EFI_MM_IO_ACCESS Io;
};



typedef struct _EFI_MM_SYSTEM_TABLE  EFI_MM_SYSTEM_TABLE;

typedef
EFI_STATUS
(*EFI_MM_INSTALL_CONFIGURATION_TABLE)(
EFI_MM_SYSTEM_TABLE    *SystemTable,
EFI_GUID               *Guid,
void                         *Table,
UINTN                        TableSize
);

typedef
EFI_STATUS
(*EFI_MM_STARTUP_THIS_AP)(
EFI_AP_PROCEDURE  Procedure,
UINTN             CpuNumber,
void          *ProcArguments
);

typedef
EFI_STATUS
(*EFI_MM_NOTIFY_FN)(
EFI_GUID  *Protocol,
void            *Interface,
EFI_HANDLE      Handle
);

typedef
EFI_STATUS
(*EFI_MM_REGISTER_PROTOCOL_NOTIFY)(
EFI_GUID     *Protocol,
EFI_MM_NOTIFY_FN   Function,
void               **Registration
);

typedef
EFI_STATUS
(*EFI_MM_INTERRUPT_MANAGE)(
EFI_GUID  *HandlerType,
void      *Context,
void        *CommBuffer,
UINTN       *CommBufferSize
);

typedef
EFI_STATUS
(*EFI_MM_HANDLER_ENTRY_POINT)(
EFI_HANDLE  DispatchHandle,
void  *Context,
void    *CommBuffer,
UINTN   *CommBufferSize
);

typedef
EFI_STATUS
(*EFI_MM_INTERRUPT_REGISTER)(
EFI_MM_HANDLER_ENTRY_POINT    Handler,
EFI_GUID                *HandlerType,
EFI_HANDLE                    *DispatchHandle
);

typedef
EFI_STATUS
(*EFI_MM_INTERRUPT_UNREGISTER)(
EFI_HANDLE  DispatchHandle
);

typedef struct _EFI_MM_ENTRY_CONTEXT {
EFI_MM_STARTUP_THIS_AP   MmStartupThisAp;
UINTN                    CurrentlyExecutingCpu;
UINTN                    NumberOfCpus;
UINTN                    *CpuSaveStateSize;
void                     **CpuSaveState;
} EFI_MM_ENTRY_CONTEXT;

typedef
void
(*EFI_MM_ENTRY_POINT)(
EFI_MM_ENTRY_CONTEXT  *MmEntryContext
);


struct _EFI_MM_SYSTEM_TABLE {
EFI_TABLE_HEADER                     Hdr;
CHAR16                               *MmFirmwareVendor;
UINT32                               MmFirmwareRevision;

EFI_MM_INSTALL_CONFIGURATION_TABLE   MmInstallConfigurationTable;

EFI_MM_CPU_IO_PROTOCOL               MmIo;

EFI_ALLOCATE_POOL                    MmAllocatePool;
EFI_FREE_POOL                        MmFreePool;
EFI_ALLOCATE_PAGES                   MmAllocatePages;
EFI_FREE_PAGES                       MmFreePages;

EFI_MM_STARTUP_THIS_AP               MmStartupThisAp;


UINTN                                CurrentlyExecutingCpu;
UINTN                                NumberOfCpus;
UINTN                                *CpuSaveStateSize;
void                                 **CpuSaveState;


UINTN                                NumberOfTableEntries;
EFI_CONFIGURATION_TABLE              *MmConfigurationTable;

EFI_INSTALL_PROTOCOL_INTERFACE       MmInstallProtocolInterface;
EFI_UNINSTALL_PROTOCOL_INTERFACE     MmUninstallProtocolInterface;
EFI_HANDLE_PROTOCOL                  MmHandleProtocol;
EFI_MM_REGISTER_PROTOCOL_NOTIFY      MmRegisterProtocolNotify;
EFI_LOCATE_HANDLE                    MmLocateHandle;
EFI_LOCATE_PROTOCOL                  MmLocateProtocol;

EFI_MM_INTERRUPT_MANAGE              MmiManage;
EFI_MM_INTERRUPT_REGISTER            MmiHandlerRegister;
EFI_MM_INTERRUPT_UNREGISTER          MmiHandlerUnRegister;
};


#define EFI_SMM_ACCESS2_PROTOCOL_GUID \
  { \
     0xc2702b74, 0x800c, 0x4131, {0x87, 0x46, 0x8f, 0xb5, 0xb8, 0x9c, 0xe4, 0xac } \
  }


typedef struct _EFI_SMM_ACCESS2_PROTOCOL  EFI_SMM_ACCESS2_PROTOCOL;

/**
  Opens the SMRAM area to be accessible by a boot-service driver.
  This function "opens" SMRAM so that it is visible while not inside of SMM. The function should 
  return EFI_UNSUPPORTED if the hardware does not support hiding of SMRAM. The function 
  should return EFI_DEVICE_ERROR if the SMRAM configuration is locked.
  @param[in] This           The EFI_SMM_ACCESS2_PROTOCOL instance.
  @retval EFI_SUCCESS       The operation was successful.
  @retval EFI_UNSUPPORTED   The system does not support opening and closing of SMRAM.
  @retval EFI_DEVICE_ERROR  SMRAM cannot be opened, perhaps because it is locked.
**/
typedef
EFI_STATUS
(*EFI_SMM_OPEN2)(
  EFI_SMM_ACCESS2_PROTOCOL  *This
  );

/**
  Inhibits access to the SMRAM.
  This function "closes" SMRAM so that it is not visible while outside of SMM. The function should 
  return EFI_UNSUPPORTED if the hardware does not support hiding of SMRAM.
  @param[in] This           The EFI_SMM_ACCESS2_PROTOCOL instance.
  @retval EFI_SUCCESS       The operation was successful.
  @retval EFI_UNSUPPORTED   The system does not support opening and closing of SMRAM.
  @retval EFI_DEVICE_ERROR  SMRAM cannot be closed.
**/
typedef
EFI_STATUS
(*EFI_SMM_CLOSE2)(
  EFI_SMM_ACCESS2_PROTOCOL  *This
  );

/**
  Inhibits access to the SMRAM.
  This function prohibits access to the SMRAM region.  This function is usually implemented such 
  that it is a write-once operation. 
  @param[in] This          The EFI_SMM_ACCESS2_PROTOCOL instance.
  @retval EFI_SUCCESS      The device was successfully locked.
  @retval EFI_UNSUPPORTED  The system does not support locking of SMRAM.
**/
typedef
EFI_STATUS
(*EFI_SMM_LOCK2)(
  EFI_SMM_ACCESS2_PROTOCOL  *This
  );

/**
  Queries the memory controller for the possible regions that will support SMRAM.
  @param[in]     This           The EFI_SMM_ACCESS2_PROTOCOL instance.
  @param[in,out] SmramMapSize   A pointer to the size, in bytes, of the SmramMemoryMap buffer.
  @param[in,out] SmramMap       A pointer to the buffer in which firmware places the current memory map.
  @retval EFI_SUCCESS           The chipset supported the given resource.
  @retval EFI_BUFFER_TOO_SMALL  The SmramMap parameter was too small.  The current buffer size 
                                needed to hold the memory map is returned in SmramMapSize.
**/
typedef
EFI_STATUS
(*EFI_SMM_CAPABILITIES2)(
  EFI_SMM_ACCESS2_PROTOCOL  *This,
  UINTN                       *SmramMapSize,
  EFI_SMRAM_DESCRIPTOR        *SmramMap
  );

///
///  EFI SMM Access2 Protocol is used to control the visibility of the SMRAM on the platform.
///  It abstracts the location and characteristics of SMRAM.  The expectation is
///  that the north bridge or memory controller would publish this protocol.
/// 
struct _EFI_SMM_ACCESS2_PROTOCOL {
  EFI_SMM_OPEN2          Open;
  EFI_SMM_CLOSE2         Close;
  EFI_SMM_LOCK2          Lock;
  EFI_SMM_CAPABILITIES2  GetCapabilities;
  ///
  /// Indicates the current state of the SMRAM. Set to TRUE if SMRAM is locked.
  ///
  BOOLEAN               LockState;
  ///
  /// Indicates the current state of the SMRAM. Set to TRUE if SMRAM is open.
  ///
  BOOLEAN               OpenState;
};


struct _EFI_MM_ACCESS_PROTOCOL {

  void *          Open;

  void *           Close;

  void *            Lock;

  void *    GetCapabilities;

  ///

  /// Indicates the current state of the MMRAM. Set to TRUE if MMRAM is locked.

  ///

  BOOLEAN               LockState;

  ///

  /// Indicates the current state of the MMRAM. Set to TRUE if MMRAM is open.

  ///

  BOOLEAN               OpenState;

};





//////////////////////////////////

enum {
EFI_BOOT_SCRIPT_IO_WRITE_OPCODE = 0x00,
EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE = 0x01,
EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE = 0x02,
EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE = 0x03,
EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE =  0x04,
EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE =  0x05,
EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE =  0x06,
EFI_BOOT_SCRIPT_STALL_OPCODE =  0x07,
EFI_BOOT_SCRIPT_DISPATCH_OPCODE =  0x08,
EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE =   0x09,
EFI_BOOT_SCRIPT_INFORMATION_OPCODE  =  0x0A,
EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE =   0x0B,
EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE =   0x0C,
EFI_BOOT_SCRIPT_IO_POLL_OPCODE  =  0x0D,
EFI_BOOT_SCRIPT_MEM_POLL_OPCODE  =  0x0E,
EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE  =  0x0F,
EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE =   0x10
};


/*
#define AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID \
	{ 0xda473d7f, 0x4b31, 0x4d63, { 0x92, 0xb7, 0x3d, 0x90, 0x5e, 0xf8, 0x4b, 0x84 } }
*/
typedef EFI_STATUS ( *AMI_SMM_VALIDATE_MEMORY_BUFFER)(void * Buffer, UINT32 BufferSize);


typedef EFI_STATUS ( *AMI_SMM_VALIDATE_MMIO_BUFFER)(void *Buffer, UINT32 BufferSize);


typedef EFI_STATUS ( *AMI_SMM_VALIDATE_SMRAM_BUFFER)(void * Buffer, UINT32 BufferSize);


typedef struct  {
    AMI_SMM_VALIDATE_MEMORY_BUFFER ValidateMemoryBuffer;
    AMI_SMM_VALIDATE_MMIO_BUFFER ValidateMmioBuffer;
    AMI_SMM_VALIDATE_SMRAM_BUFFER ValidateSmramBuffer;
} AMI_SMM_BUFFER_VALIDATION_PROTOCOL;

extern EFI_GUID gAmiSmmBufferValidationProtocolGuid;



enum {
MSR0000_0000_Load_Store_MCA_Address = 0,
MSR0000_0001_Load_Store_MCA_Status = 1,
MSR0000_0010_Time_Stamp_Counter_TSC = 16,
MSR0000_001B_APIC_Base_Address_APIC_BAR = 27,
MSR0000_002A_Cluster_ID_EBL_CR_POWERON = 42,
MSR0000_00E7_Max_Performance_Frequency_Clock_Count_MPERF = 231,
MSR0000_00E8_Actual_Performance_Frequency_Clock_Count_APERF = 232,
MSR0000_00FE_MTRR_Capabilities_MTRRcap = 254,
MSR0000_0174_SYSENTER_CS_SYSENTER_CS = 372,
MSR0000_0175_SYSENTER_ESP_SYSENTER_ESP = 373,
MSR0000_0176_SYSENTER_EIP_SYSENTER_EIP = 374,
MSR0000_0179_Global_Machine_Check_Capabilities_MCG_CAP = 377,
MSR0000_017A_Global_Machine_Check_Status_MCG_STAT = 378,
MSR0000_017B_Global_Machine_Check_Exception_Reporting_Control_MCG_CTL = 379,
MSR0000_01D9_Debug_Control_DBG_CTL_MSR = 473,
MSR0000_01DB_Last_Branch_From_IP_BR_FROM = 475,
MSR0000_01DC_Last_Branch_To_IP_BR_TO = 476,
MSR0000_01DD_Last_Exception_From_IP = 477,
MSR0000_01DE_Last_Exception_To_IP = 478,
MSR0000_0200_Variable_Size_MTRRs_Base = 512,
MSR0000_0202_Variable_Size_MTRRs_Base = 514,
MSR0000_0204_Variable_Size_MTRRs_Base = 516,
MSR0000_0206_Variable_Size_MTRRs_Base = 518,
MSR0000_0208_Variable_Size_MTRRs_Base = 520,
MSR0000_020A_Variable_Size_MTRRs_Base = 522,
MSR0000_020C_Variable_Size_MTRRs_Base = 524,
MSR0000_020E_Variable_Size_MTRRs_Base = 526,
MSR0000_0201_Variable_Size_MTRRs_Mask = 513,
MSR0000_0203_Variable_Size_MTRRs_Mask = 515,
MSR0000_0205_Variable_Size_MTRRs_Mask = 517,
MSR0000_0207_Variable_Size_MTRRs_Mask = 519,
MSR0000_0209_Variable_Size_MTRRs_Mask = 521,
MSR0000_020B_Variable_Size_MTRRs_Mask = 523,
MSR0000_020D_Variable_Size_MTRRs_Mask = 525,
MSR0000_020F_Variable_Size_MTRRs_Mask = 527,
MSR0000_0250_64K_70000_64K_60000_64K_50000_64K_40000_64K_30000_64K_20000_64K_10000_64K_00000 = 592,
MSR0000_0258_16K_9C000_16K_98000_16K_94000_16K_90000_16K_8C000_16K_88000_16K_84000_16K_80000 = 600,
MSR0000_0259_16K_BC000_16K_B8000_16K_B4000_16K_B0000_16K_AC000_16K_A8000_16K_A4000_16K_A0000 = 601,
MSR0000_0268_4K_C7000_4K_C6000_4K_C5000_4K_C4000_4K_C3000_4K_C2000_4K_C1000_4K_C0000 = 616,
MSR0000_026F_4K_FF000_4K_FE000_4K_FD000_4K_FC000_4K_FB000_4K_FA000_4K_F9000_4K_F8000 = 623,
MSR0000_0269_4K_CF000_4K_CE000_4K_CD000_4K_CC000_4K_CB000_4K_CA000_4K_C9000_4K_C8000 = 617,
MSR0000_026A_4K_D7000_4K_D6000_4K_D5000_4K_D4000_4K_D3000_4K_D2000_4K_D1000_4K_D0000 = 618,
MSR0000_026B_4K_DF000_4K_DE000_4K_DD000_4K_DC000_4K_DB000_4K_DA000_4K_D9000_4K_D8000 = 619,
MSR0000_026C_4K_E7000_4K_E6000_4K_E5000_4K_E4000_4K_E3000_4K_E2000_4K_E1000_4K_E0000 = 620,
MSR0000_026D_4K_EF000_4K_EE000_4K_ED000_4K_EC000_4K_EB000_4K_EA000_4K_E9000_4K_E8000 = 621,
MSR0000_026E_4K_F7000_4K_F6000_4K_F5000_4K_F4000_4K_F3000_4K_F2000_4K_F1000_4K_F0000 = 622,
MSR0000_0277_Page_Attribute_Table_PAT = 631,
MSR0000_02FF_MTRR_Default_Memory_Type_MTRRdefType = 767,
MSR0000_0400_MC0_Machine_Check_Control_MC0_CTL = 1024,
MSR0000_0401_MC0_Machine_Check_Status_MC0_STATUS = 1025,
MSR0000_0402_MC0_Machine_Check_Address_MC0_ADDR = 1026,
MSR0000_0403_MC0_Machine_Check_Miscellaneous_MC0_MISC = 1027,
MSR0000_0404_MC1_Machine_Check_Control_MC1_CTL = 1028,
MSR0000_0405_MC1_Machine_Check_Status_MC1_STATUS = 1029,
MSR0000_0406_MC1_Machine_Check_Address_MC1_ADDR = 1030,
MSR0000_0407_MC1_Machine_Check_Miscellaneous_MC1_MISC = 1031,
MSR0000_0408_MC2_Machine_Check_Control_MC2_CTL = 1032,
MSR0000_0409_MC2_Machine_Check_Status_MC2_STATUS = 1033,
MSR0000_040A_MC2_Machine_Check_Address_MC2_ADDR = 1034,
MSR0000_040B_MC2_Machine_Check_Miscellaneous_MC2_MISC = 1035,
MSR0000_040C_MC3_Machine_Check_Control_MC3_CTL = 1036,
MSR0000_040D_MC3_Machine_Check_Status_MC3_STATUS = 1037,
MSR0000_040E_MC3_Machine_Check_Address_MC3_ADDR = 1038,
MSR0000_040F_MC3_Machine_Check_Miscellaneous_MC3_MISC = 1039,
MSR0000_0410_MC4_Machine_Check_Control_MC4_CTL = 1040,
MSR0000_0411_MC4_Machine_Check_Status_MC4_STATUS = 1041,
MSR0000_0412_MC4_Machine_Check_Address_MC4_ADDR = 1042,
MSR0000_0414_MC5_Machine_Check_Control_MC5_CTL = 1044,
MSR0000_0415_MC5_Machine_Check_Status_MC5_STATUS = 1045,
MSR0000_0416_MC5_Machine_Check_Address_MC5_ADDR = 1046,
MSRC000_0080_Extended_Feature_Enable_EFER = 3221225600,
MSRC000_0081_SYSCALL_Target_Address_STAR = 3221225601,
MSRC000_0082_Long_Mode_SYSCALL_Target_Address_STAR64 = 3221225602,
MSRC000_0083_Compatibility_Mode_SYSCALL_Target_Address_STARCOMPAT = 3221225603,
MSRC000_0084_SYSCALL_Flag_Mask_SYSCALL_FLAG_MASK = 3221225604,
MSRC000_0100_FS_Base_FS_BASE = 3221225728,
MSRC000_0101_GS_Base_GS_BASE = 3221225729,
MSRC000_0102_Kernel_GS_Base_KernelGSbase = 3221225730,
MSRC000_0103_Auxiliary_Time_Stamp_Counter_TSC_AUX = 3221225731,
MSRC000_0104_Time_Stamp_Counter_Ratio_TscRateMsr = 3221225732,
MSRC000_0408_NB_Machine_Check_Misc_4_Link_Thresholding_1_MC4_MISC1 = 3221226504,
MSRC000_0409_Reserved = 3221226505,
MSRC000_040A_Reserved = 3221226506,
MSRC000_040F_Reserved = 3221226511,
MSRC001_0000_Performance_Event_Select_PERF_CTL3_0 = 3221291008,
MSRC001_0001_Performance_Event_Select_PERF_CTL3_0 = 3221291009,
MSRC001_0002_Performance_Event_Select_PERF_CTL3_0 = 3221291010,
MSRC001_0003_Performance_Event_Select_PERF_CTL3_0 = 3221291011,
MSRC001_0004_Performance_Event_Counter_PERF_CTR3_0 = 3221291012,
MSRC001_0005_Performance_Event_Counter_PERF_CTR3_0 = 3221291013,
MSRC001_0006_Performance_Event_Counter_PERF_CTR3_0 = 3221291014,
MSRC001_0007_Performance_Event_Counter_PERF_CTR3_0 = 3221291015,
MSRC001_0010_System_Configuration_SYS_CFG = 3221291024,
MSRC001_0015_Hardware_Configuration_HWCR = 3221291029,
MSRC001_0016_IO_Range_Base_IORR_BASE1_0 = 3221291030,
MSRC001_0017_IO_Range_Mask_IORR_MASK1_0 = 3221291031,
MSRC001_0018_IO_Range_Base_IORR_BASE1_0 = 3221291032,
MSRC001_0019_IO_Range_Mask_IORR_MASK1_0 = 3221291033,
MSRC001_001A_Top_Of_Memory_TOP_MEM = 3221291034,
MSRC001_001D_Top_Of_Memory_2_TOM2 = 3221291037,
MSRC001_001F_Northbridge_Configuration_1_NB_CFG1 = 3221291039,
MSRC001_0022_Machine_Check_Exception_Redirection = 3221291042,
MSRC001_0030_D18F5x198_x1___D18F5x198_x0 = 3221291056,
MSRC001_0031_D18F5x198_x3___D18F5x198_x2 = 3221291057,
MSRC001_0032_D18F5x198_x5___D18F5x198_x4 = 3221291058,
MSRC001_0033_D18F5x198_x7___D18F5x198_x6 = 3221291059,
MSRC001_0034_D18F5x198_x9___D18F5x198_x8 = 3221291060,
MSRC001_0035_D18F5x198_xB___D18F5x198_xA = 3221291061,
MSRC001_003E_Hardware_Thermal_Control_HTC = 3221291070,
MSRC001_0044_DC_Machine_Check_Control_Mask_MC0_CTL_MASK = 3221291076,
MSRC001_0045_IC_Machine_Check_Control_Mask_MC1_CTL_MASK = 3221291077,
MSRC001_0046_BU_Machine_Check_Control_Mask_MC2_CTL_MASK = 3221291078,
MSRC001_0047_Reserved_MC3_CTL_MASK = 3221291079,
MSRC001_0048_NB_Machine_Check_Control_Mask_MC4_CTL_MASK = 3221291080,
MSRC001_0049_FR_Machine_Check_Control_Mask_MC5_CTL_MASK = 3221291081,
MSRC001_0050_IO_Trap_SMI_ON_IO_TRAP_3_0 = 3221291088,
MSRC001_0051_IO_Trap_SMI_ON_IO_TRAP_3_0 = 3221291089,
MSRC001_0052_IO_Trap_SMI_ON_IO_TRAP_3_0 = 3221291090,
MSRC001_0053_IO_Trap_SMI_ON_IO_TRAP_3_0 = 3221291091,
MSRC001_0054_IO_Trap_Control_SMI_ON_IO_TRAP_CTL_STS = 3221291092,
MSRC001_0055_Interrupt_Pending = 3221291093,
MSRC001_0056_SMI_Trigger_IO_Cycle = 3221291094,
MSRC001_0058_MMIO_Configuration_Base_Address = 3221291096,
MSRC001_0060_BIST_Results = 3221291104,
MSRC001_0061_P_state_Current_Limit = 3221291105,
MSRC001_0062_P_state_Control = 3221291106,
MSRC001_0063_P_state_Status = 3221291107,
MSRC001_0064_P_state_0 = 3221291108,
MSRC001_0065_P_state_1 = 3221291109,
MSRC001_0066_P_state_2 = 3221291110,
MSRC001_0067_P_state_3 = 3221291111,
MSRC001_0068_P_state_4 = 3221291112,
MSRC001_0069_P_state_5 = 3221291113,
MSRC001_006A_P_state_6 = 3221291114,
MSRC001_006B_P_state_7 = 3221291115,
MSRC001_0070_COFVID_Control = 3221291120,
MSRC001_0071_COFVID_Status = 3221291121,
MSRC001_0073_C_state_Base_Address = 3221291123,
MSRC001_0074_CPU_Watchdog_Timer_CpuWdtCfg = 3221291124,
MSRC001_007A_Compute_Unit_Power_Accumulator = 3221291130,
MSRC001_007B_Max_Compute_Unit_Power_Accumulator = 3221291131,
MSRC001_0111_SMM_Base_Address_SMM_BASE = 3221291281,
MSRC001_0112_SMM_TSeg_Base_Address_SMMAddr = 3221291282,
MSRC001_0113_SMM_TSeg_Mask_SMMMask = 3221291283,
MSRC001_0114_Virtual_Machine_Control_VM_CR = 3221291284,
MSRC001_0115_IGNNE = 3221291285,
MSRC001_0116_SMM_Control_SMM_CTL = 3221291286,
MSRC001_0117_Virtual_Machine_Host_Save_Physical_Address_VM_HSAVE_PA = 3221291287,
MSRC001_0118_SVM_Lock_Key = 3221291288,
MSRC001_011A_Local_SMI_Status = 3221291290,
MSRC001_0140_OS_Visible_Work_around_MSR0_OSVW_ID_Length = 3221291328,
MSRC001_0141_OS_Visible_Work_around_MSR1_OSVW_Status = 3221291329,
MSRC001_0230_L2I_Performance_Event_Select_L2I_PERF_CTL3_0 = 3221291568,
MSRC001_0232_L2I_Performance_Event_Select_L2I_PERF_CTL3_0 = 3221291570,
MSRC001_0234_L2I_Performance_Event_Select_L2I_PERF_CTL3_0 = 3221291572,
MSRC001_0236_L2I_Performance_Event_Select_L2I_PERF_CTL3_0 = 3221291574,
MSRC001_0231_L2I_Performance_Event_Counter_L2I_PERF_CTR3_0 = 3221291569,
MSRC001_0233_L2I_Performance_Event_Counter_L2I_PERF_CTR3_0 = 3221291571,
MSRC001_0235_L2I_Performance_Event_Counter_L2I_PERF_CTR3_0 = 3221291573,
MSRC001_0237_L2I_Performance_Event_Counter_L2I_PERF_CTR3_0 = 3221291575,
MSRC001_0240_Northbridge_Performance_Event_Select_NB_PERF_CTL3_0 = 3221291584,
MSRC001_0242_Northbridge_Performance_Event_Select_NB_PERF_CTL3_0 = 3221291586,
MSRC001_0244_Northbridge_Performance_Event_Select_NB_PERF_CTL3_0 = 3221291588,
MSRC001_0246_Northbridge_Performance_Event_Select_NB_PERF_CTL3_0 = 3221291590,
MSRC001_0241_Northbridge_Performance_Event_Counter_NB_PERF_CTR3_0 = 3221291585,
MSRC001_0243_Northbridge_Performance_Event_Counter_NB_PERF_CTR3_0 = 3221291587,
MSRC001_0245_Northbridge_Performance_Event_Counter_NB_PERF_CTR3_0 = 3221291589,
MSRC001_0247_Northbridge_Performance_Event_Counter_NB_PERF_CTR3_0 = 3221291591,
MSRC001_0280_Performance_Time_Stamp_Counter_CU_PTSC = 3221291648,
MSRC001_1004_CPUID_Features_Features = 3221295108,
MSRC001_1005_Extended_CPUID_Features_ExtFeatures = 3221295109,
MSRC001_1019_DR1 = 3221295129,
MSRC001_101A_DR2 = 3221295130,
MSRC001_101B_DR3 = 3221295131,
MSRC001_1020_Load_Store_Configuration_LS_CFG = 3221295136,
MSRC001_1021_Instruction_Cache_Configuration_IC_CFG = 3221295137,
MSRC001_1022_Data_Cache_Configuration_DC_CFG = 3221295138,
MSRC001_1023_Bus_Unit_Configuration_BU_CFG = 3221295139,
MSRC001_1027_Address_Mask_For_DR0_Breakpoints_DR0_ADDR_MASK = 3221295143,
MSRC001_1028_Floating_Point_Configuration_FP_CFG = 3221295144,
MSRC001_102A_Bus_Unit_Configuration_2_BU_CFG2 = 3221295146,
MSRC001_1030_IBS_Fetch_Control_IbsFetchCtl = 3221295152,
MSRC001_1031_IBS_Fetch_Linear_Address_IbsFetchLinAd = 3221295153,
MSRC001_1032_IBS_Fetch_Physical_Address_IbsFetchPhysAd = 3221295154,
MSRC001_1033_IBS_Execution_Control_IbsOpCtl = 3221295155,
MSRC001_1034_IBS_Op_Logical_Address_IbsOpRip = 3221295156,
MSRC001_1035_IBS_Op_Data_IbsOpData = 3221295157,
MSRC001_1036_IBS_Op_Data_2_IbsOpData2 = 3221295158,
MSRC001_1037_IBS_Op_Data_3_IbsOpData3 = 3221295159,
MSRC001_1038_IBS_DC_Linear_Address_IbsDcLinAd = 3221295160,
MSRC001_1039_IBS_DC_Physical_Address_IbsDcPhysAd = 3221295161,
MSRC001_103A_IBS_Control = 3221295162,
MSRC001_103B_IBS_Branch_Target_Address_BP_IBSTGT_RIP = 3221295163,
MSRC001_1090_Processor_Feedback_Constants_0 = 3221295248,
MSRC001_10A0_L2I_Configuration_L2I_CFG = 3221295264,
MSRC001_0132_RMP_BASE = 0xC0010132,
MSRC001_0132_RMP_END = 0xC0010133,
};




typedef enum {
  EFI_MM_SAVE_STATE_IO_TYPE_INPUT      = 1,
  EFI_MM_SAVE_STATE_IO_TYPE_OUTPUT     = 2,
  EFI_MM_SAVE_STATE_IO_TYPE_STRING     = 4,
  EFI_MM_SAVE_STATE_IO_TYPE_REP_PREFIX = 8
} EFI_MM_SAVE_STATE_IO_TYPE;
typedef enum {
  EFI_MM_SAVE_STATE_IO_WIDTH_UINT8  = 0,
  EFI_MM_SAVE_STATE_IO_WIDTH_UINT16 = 1,
  EFI_MM_SAVE_STATE_IO_WIDTH_UINT32 = 2,
  EFI_MM_SAVE_STATE_IO_WIDTH_UINT64 = 3
} EFI_MM_SAVE_STATE_IO_WIDTH;

typedef struct _EFI_MM_SAVE_STATE_IO_INFO {
  ///
  /// For input instruction (IN, INS), this is data read before the MMI occurred. For output
  /// instructions (OUT, OUTS) this is data that was written before the MMI occurred. The
  /// width of the data is specified by IoWidth.
  ///
  UINT64                        IoData;
  ///
  /// The I/O port that was being accessed when the MMI was triggered.
  ///
  UINT16                        IoPort;
  ///
  /// Defines the size width (UINT8, UINT16, UINT32, UINT64) for IoData.
  ///
  EFI_MM_SAVE_STATE_IO_WIDTH    IoWidth;
  ///
  /// Defines type of I/O instruction.
  ///
  EFI_MM_SAVE_STATE_IO_TYPE     IoType;
} EFI_MM_SAVE_STATE_IO_INFO;

#define EFI_MM_IO_TRAP_DISPATCH_PROTOCOL_GUID \
 { 0x58dc368d, 0x7bfa, 0x4e77, \
 0xab, 0xbc, 0xe, 0x29, 0x41, 0x8d, 0xf9, 0x30 }

extern EFI_GUID gEfiMmIoTrapDispatchProtocol;

typedef enum {
 WriteTrap,
 ReadTrap,
 ReadWriteTrap,
 IoTrapTypeMaximum
} EFI_MM_IO_TRAP_DISPATCH_TYPE;


typedef struct {
 UINT16 Address;
 UINT16 Length;
 EFI_MM_IO_TRAP_DISPATCH_TYPE Type;
} EFI_MM_IO_TRAP_REGISTER_CONTEXT;




typedef EFI_STATUS
(*EFI_MM_IO_TRAP_DISPATCH_REGISTER) (
 void *This,
 EFI_MM_HANDLER_ENTRY_POINT DispatchFunction,
 EFI_MM_IO_TRAP_REGISTER_CONTEXT *RegisterContext,
 EFI_HANDLE *DispatchHandle
 );

 typedef EFI_STATUS
(*EFI_MM_IO_TRAP_DISPATCH_UNREGISTER)(
  void *This, 
  EFI_HANDLE                          DispatchHandle
  );

 typedef struct _EFI_MM_IO_TRAP_DISPATCH_PROTOCOL {
 EFI_MM_IO_TRAP_DISPATCH_REGISTER Register;
 EFI_MM_IO_TRAP_DISPATCH_UNREGISTER UnRegister;
} EFI_MM_IO_TRAP_DISPATCH_PROTOCOL;





#define SID_LENGTH                        0x20
#define OPAL_MSID_LENGHT                  128
typedef enum {
    //
    // Represents the device ownership is unknown because starting a session as the SID authority with the ADMIN SP
    //was unsuccessful with the provided PIN
    //
    OpalOwnershipUnknown,

    //
    // Represents that the ADMIN SP SID authority contains the same PIN as the MSID PIN
    //
    OpalOwnershipNobody,
} OPAL_OWNER_SHIP;

typedef struct {
    //
    // Opal SSC 1 support  (0 - not supported, 1 - supported)
    //
    UINT32 OpalSsc1 : 1;

    //
    // Opal SSC 2support  (0 - not supported, 1 - supported)
    //
    UINT32 OpalSsc2 : 1;

    //
    // Opal SSC Lite support  (0 - not supported, 1 - supported)
    //
    UINT32 OpalSscLite : 1;

    //
    // Pyrite SSC support  (0 - not supported, 1 - supported)
    //
    UINT32 PyriteSsc : 1;

    //
    // Security protocol 1 support  (0 - not supported, 1 - supported)
    //
    UINT32 Sp1 : 1;

    //
    // Security protocol 2 support  (0 - not supported, 1 - supported)
    //
    UINT32 Sp2 : 1;

    //
    // Security protocol IEEE1667 support  (0 - not supported, 1 - supported)
    //
    UINT32 SpIeee1667 : 1;

    //
    // Media encryption supported (0 - not supported, 1 - supported)
    //
    UINT32 MediaEncryption : 1;

    //
    // Initial C_PIN_SID PIN Indicator
    //  0 - The initial C_PIN_SID PIN value is NOT equal to the C_PIN_MSID PIN value
    //  1 - The initial C_PIN_SID PIN value is equal to the C_PIN_MSID PIN value
    //
    UINT32 InitCpinIndicator : 1;

    //
    // Behavior of C_PIN_SID PIN upon TPer Revert
    //  0 - The initial C_PIN_SID PIN value is NOT equal to the C_PIN_MSID PIN value
    //  1 - The initial C_PIN_SID PIN value is equal to the C_PIN_MSID PIN value
    //
    UINT32 CpinUponRevert : 1;

    //
    // Media encryption supported (0 - not supported, 1 - supported)
    //
    UINT32 BlockSid : 1;

    //
    // Pyrite SSC V2 support  (0 - not supported, 1 - supported)
    //
    UINT32 PyriteSscV2 : 1;

    //
    // Supported Data Removal Mechanism support  (0 - not supported, 1 - supported)
    //
    UINT32 DataRemoval : 1;
} OPAL_DISK_SUPPORT_ATTRIBUTE;


typedef struct _TCG_LEVEL0_FEATURE_DESCRIPTOR_HEADER {
  UINT16 FeatureCode_BE;
  UINT8  Reserved : 4;
  UINT8  Version : 4;
  UINT8  Length;     // length of feature dependent data in bytes
} TCG_LEVEL0_FEATURE_DESCRIPTOR_HEADER;


typedef struct {
  TCG_LEVEL0_FEATURE_DESCRIPTOR_HEADER Header;
  UINT8                                LockingSupported : 1;
  UINT8                                LockingEnabled : 1;   // means the locking security provider (SP) is enabled
  UINT8                                Locked : 1;   // means at least 1 locking range is enabled
  UINT8                                MediaEncryption : 1;
  UINT8                                MbrEnabled : 1;
  UINT8                                MbrDone : 1;
  UINT8                                Reserved : 2;
  UINT8                                Reserved515[11];
} TCG_LOCKING_FEATURE_DESCRIPTOR;


typedef struct {
  TCG_LEVEL0_FEATURE_DESCRIPTOR_HEADER Header;
  UINT8                                SIDValueState : 1;
  UINT8                                SIDBlockedState : 1;
  UINT8                                Reserved4 : 6;
  UINT8                                HardwareReset : 1;
  UINT8                                Reserved5 : 7;
  UINT8                                Reserved615[10];
} TCG_BLOCK_SID_FEATURE_DESCRIPTOR;

typedef struct {
  UINT32                                          MsidLength;             // Byte length of MSID Pin for device
  UINT8                                           Msid[OPAL_MSID_LENGHT]; // MSID Pin for device
  UINT32                                          MediaId;                // MediaId is used by Ssc Protocol.
  void                        *OpalDevicePath;
  UINT16                                          OpalBaseComId;          // Opal SSC 1 base com id.
  OPAL_OWNER_SHIP                                 Owner;
  OPAL_DISK_SUPPORT_ATTRIBUTE                     SupportedAttributes;
  TCG_LOCKING_FEATURE_DESCRIPTOR                  LockingFeature;         // Locking Feature Descriptor retrieved from performing a Level 0 Discovery
  TCG_BLOCK_SID_FEATURE_DESCRIPTOR                BlockSidFeature;
  UINT32                                          EstimateTimeCost;
} OPAL_DISK_INFO;


#define DEVICE_MODEL_NAME_STRING_LENGTH  40
#define DEVICE_MODEL_NAME_STRING_SIZE    80

typedef struct {
  UINT16                                HddSecurityStatus;
  CHAR16                                HddModelString[DEVICE_MODEL_NAME_STRING_LENGTH];
  UINT16                                MasterPasswordIdentifier;
  UINT8                                 ControllerMode;
  UINT16                                ControllerNumber;
  UINT16                                PortNumber;
  UINT16                                PortMulNumber;
  UINT16                                MappedPort;
  UINTN                                 PciSeg;
  UINTN                                 PciBus;
  UINTN                                 PciDevice;
  UINTN                                 PciFunction;
  EFI_HANDLE                            DeviceHandleInDxe;
  EFI_HANDLE                            DeviceHandleInSmm;
  UINT8                                 MaxPasswordLengthSupport;

  //
  //  TCG Stoage Security Supported
  //
  BOOLEAN                               StorageTcgSecuritySupported;

  void *HddInfoExtPtr;
} HDD_PASSWORD_HDD_INFO;
#define HDD_PASSWORD_MAX_NUMBER         32

typedef struct {
  UINTN                                   Signature;
  LIST_ENTRY                              Link;
  UINT32                                  BlockIoMediaId;
  EFI_HANDLE                              DeviceHandleInDxe;
  EFI_HANDLE                              DeviceHandleInSmm;
  void *StorageSecurityCommandInDxe;
  void *StorageSecurityCommandInSmm;
  HDD_PASSWORD_HDD_INFO                   HddInfo;
  OPAL_DISK_INFO                          OpalDisk;
  UINT8                                   CachedPassword[HDD_PASSWORD_MAX_NUMBER];
  UINTN                                   CachedPasswordLength;
  void *DevicePath;
  BOOLEAN                                 InstalledByInsyde;
} HDD_PASSWORD_HDD_INFO_PRIVATE;


struct PolicyEntryHeader {
    UINT32 Version;
    UINT32 Type;
    UINT32 EntrySize;
}


struct PolicyRoot {
    UINT32 Version;
    UINT32 PolicyRootSize;
    UINT32 Type;
    UINT32 Offset;
    UINT32 Count;
    UINT8  AccessAttr;
    UINT8  Reserved[3];
}

struct MemoryPolicyEntry {
    PolicyEntryHeader Header;
    UINT64 BaseAddress; // base addr of memory
    UINT64 Size;
    UINT32 MemAttributes;
    UINT32 Reserved;
}

struct IoPolicyEntry {
    PolicyEntryHeader Header;
    UINT16 IoAddress;
    UINT16 Size;
    UINT16 Attributes;
}

struct MsrPolicyEntry {
    PolicyEntryHeader Header;
    UINT32 MsrAddress;
    UINT16 Size;
    UINT16 Attributes;
}

struct InstructionPolicyEntry {
    PolicyEntryHeader Header;
    UINT16 InstructionIndex;
    UINT16 Attributes;
}

struct SaveStatePolicyEntry {
    PolicyEntryHeader Header;
    UINT32 SaveStateIndex;
    UINT32 AccessCondition;
    UINT32 Attributes;
}

typedef enum {
    INVALID = 0,
    MEMORY,
    IO,
    MSR,
    INSTRUCTION,
    SAVESTATE
} POLICY_TYPE;

typedef enum {
    SECURE_POLICY_INSTRUCTION_CLI = 0,
    SECURE_POLICY_INSTRUCTION_WBINVD,
    SECURE_POLICY_INSTRUCTION_HLT,
    // Do not append after COUNT entry
    SECURE_POLICY_INSTRUCTION_COUNT
} SECURE_POLICY_INSTRUCTION;

typedef enum {
    SECURE_POLICY_SVST_RAX              = 0,
    SECURE_POLICY_SVST_IO_TRAP          = 1,
    // Do not append after COUNT entry
    SECURE_POLICY_SVST_COUNT            = 2
} SECURE_POLICY_SVST;

typedef enum {
    SECURE_POLICY_SVST_UNCONDITIONAL    = 0,
    SECURE_POLICY_SVST_CONDITION_IO_RD  = 1,
    SECURE_POLICY_SVST_CONDITION_IO_WR  = 2,
    // Do not append after COUNT entry
    SECURE_POLICY_SVST_CONDITION_COUNT  = 3
} SECURE_POLICY_SVST_CONDITION;



typedef enum {
  EfiUsbDataIn,
  EfiUsbData,
  EfiUsbNoData
} EFI_USB_DATA_DIRECTION;

typedef struct {
  UINT8     RequestType;
  UINT8     Request;
  UINT16    Value;
  UINT16    Index;
  UINT16    Length;
} USB_DEVICE_REQUEST;

typedef struct {
  UINT8     Length;
  UINT8     DescriptorType;
  UINT16    BcdUSB;
  UINT8     DeviceClass;
  UINT8     DeviceSubClass;
  UINT8     DeviceProtocol;
  UINT8     MaxPacketSize0;
  UINT16    IdVendor;
  UINT16    IdProduct;
  UINT16    BcdDevice;
  UINT8     StrManufacturer;
  UINT8     StrProduct;
  UINT8     StrSerialNumber;
  UINT8     NumConfigurations;
} USB_DEVICE_DESCRIPTOR;

typedef struct {
  UINT8     Length;
  UINT8     DescriptorType;
  UINT16    TotalLength;
  UINT8     NumInterfaces;
  UINT8     ConfigurationValue;
  UINT8     Configuration;
  UINT8     Attributes;
  UINT8     MaxPower;
} USB_CONFIG_DESCRIPTOR;

typedef struct {
  UINT8    Length;
  UINT8    DescriptorType;
  UINT8    InterfaceNumber;
  UINT8    AlternateSetting;
  UINT8    NumEndpoints;
  UINT8    InterfaceClass;
  UINT8    InterfaceSubClass;
  UINT8    InterfaceProtocol;
  UINT8    Interface;
} USB_INTERFACE_DESCRIPTOR;

typedef struct {
  UINT8     Length;
  UINT8     DescriptorType;
  UINT8     EndpointAddress;
  UINT8     Attributes;
  UINT16    MaxPacketSize;
  UINT8     Interval;
} USB_ENDPOINT_DESCRIPTOR;

typedef USB_DEVICE_REQUEST       EFI_USB_DEVICE_REQUEST;
typedef USB_DEVICE_DESCRIPTOR    EFI_USB_DEVICE_DESCRIPTOR;
typedef USB_CONFIG_DESCRIPTOR    EFI_USB_CONFIG_DESCRIPTOR;
typedef USB_INTERFACE_DESCRIPTOR EFI_USB_INTERFACE_DESCRIPTOR;
typedef USB_ENDPOINT_DESCRIPTOR  EFI_USB_ENDPOINT_DESCRIPTOR;


typedef
EFI_STATUS
(*EFI_ASYNC_USB_TRANSFER_CALLBACK)(
  void         *Data,
  UINTN        DataLength,
  void         *Context,
  UINT32       Status
  );

struct _EFI_USB_IO_PROTOCOL;



typedef
EFI_STATUS
(*EFI_USB_IO_CONTROL_TRANSFER)(
  EFI_USB_IO_PROTOCOL                        *This,
  void                     *Request,
  EFI_USB_DATA_DIRECTION                     Direction,
  UINT32                                     Time,
   void                                   *Data,
  UINTN                                      DataLength ,
   UINT32                                    *Status
  );

typedef
EFI_STATUS
( *EFI_USB_IO_BULK_TRANSFER)(
  EFI_USB_IO_PROTOCOL            *This,
  UINT8                          DeviceEndpoint,
   void                       *Data,
   UINTN                      *DataLength,
  UINTN                          Time,
   UINT32                        *Status
  );

  typedef
EFI_STATUS
( *EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER)(
  EFI_USB_IO_PROTOCOL                                 *This,
  UINT8                                               DeviceEndpoint,
  BOOLEAN                                             IsNewTransfer,
  UINTN                                               PollingInterval    ,
  UINTN                                               DataLength         ,
  EFI_ASYNC_USB_TRANSFER_CALLBACK                     InterruptCallBack  ,
  void                                                *Context 
  );


typedef
EFI_STATUS
( *EFI_USB_IO_ISOCHRONOUS_TRANSFER)(
  EFI_USB_IO_PROTOCOL            *This,
      UINT8                      DeviceEndpoint,
   void                       *Data,
      UINTN                      DataLength,
      UINT32                     *Status
  );

  typedef
EFI_STATUS
( *EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER)(
  EFI_USB_IO_PROTOCOL              *This,
  UINT8                            DeviceEndpoint,
   void                         *Data,
      UINTN                        DataLength,
  EFI_ASYNC_USB_TRANSFER_CALLBACK  IsochronousCallBack,
  void                             *Context 
  );

typedef
EFI_STATUS
( *EFI_USB_IO_SYNC_INTERRUPT_TRANSFER)(
  EFI_USB_IO_PROTOCOL            *This,
      UINT8                      DeviceEndpoint,
   void                       *Data,
   UINTN                      *DataLength,
      UINTN                      Time,
      UINT32                     *Status
  );

typedef
EFI_STATUS
( *EFI_USB_IO_PORT_RESET)(
  EFI_USB_IO_PROTOCOL    *This
  );

typedef
EFI_STATUS
( *EFI_USB_IO_GET_DEVICE_DESCRIPTOR)(
  EFI_USB_IO_PROTOCOL            *This,
   EFI_USB_DEVICE_DESCRIPTOR     *DeviceDescriptor
  );

  typedef
EFI_STATUS
( *EFI_USB_IO_GET_CONFIG_DESCRIPTOR)(
  EFI_USB_IO_PROTOCOL            *This,
   EFI_USB_CONFIG_DESCRIPTOR     *ConfigurationDescriptor
  );

  typedef
EFI_STATUS
( *EFI_USB_IO_GET_INTERFACE_DESCRIPTOR)(
  EFI_USB_IO_PROTOCOL            *This,
   EFI_USB_INTERFACE_DESCRIPTOR  *InterfaceDescriptor
  );

  typedef
EFI_STATUS
( *EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR)(
  EFI_USB_IO_PROTOCOL            *This,
   UINT8                         EndpointIndex,
   EFI_USB_ENDPOINT_DESCRIPTOR   *EndpointDescriptor
  );


  typedef
EFI_STATUS
( *EFI_USB_IO_GET_STRING_DESCRIPTOR)(
  EFI_USB_IO_PROTOCOL            *This,
   UINT16                        LangID,
   UINT8                         StringID,
   CHAR16                        **String
  );


  typedef
EFI_STATUS
( *EFI_USB_IO_GET_SUPPORTED_LANGUAGE)(
  EFI_USB_IO_PROTOCOL            *This,
   UINT16                        **LangIDTable,
   UINT16                        *TableSize
  );

typedef struct _EFI_USB_IO_PROTOCOL {

  EFI_USB_IO_CONTROL_TRANSFER              UsbControlTransfer;
  EFI_USB_IO_BULK_TRANSFER                 UsbBulkTransfer;
  EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER      UsbAsyncInterruptTransfer;
  EFI_USB_IO_SYNC_INTERRUPT_TRANSFER       UsbSyncInterruptTransfer;
  EFI_USB_IO_ISOCHRONOUS_TRANSFER          UsbIsochronousTransfer;
  EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER    UsbAsyncIsochronousTransfer;

 
  EFI_USB_IO_GET_DEVICE_DESCRIPTOR         UsbGetDeviceDescriptor;
  EFI_USB_IO_GET_CONFIG_DESCRIPTOR         UsbGetConfigDescriptor;
  EFI_USB_IO_GET_INTERFACE_DESCRIPTOR      UsbGetInterfaceDescriptor;
  EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR       UsbGetEndpointDescriptor;
  EFI_USB_IO_GET_STRING_DESCRIPTOR         UsbGetStringDescriptor;
  EFI_USB_IO_GET_SUPPORTED_LANGUAGE        UsbGetSupportedLanguages;


  EFI_USB_IO_PORT_RESET                    UsbPortReset;
} EFI_USB_IO_PROTOCOL;


typedef struct {
  UINT8    Dependencies[1];
} EFI_FIRMWARE_IMAGE_DEP;

struct EFI_FIRMWARE_MANAGEMENT_PROTOCOL {};

typedef struct { 
  UINT8       ImageIndex;  
  EFI_GUID    ImageTypeId;  
  UINT64      ImageId;  
  CHAR16      *ImageIdName;  
  UINT32      Version;  
  CHAR16      *VersionName;  
  UINTN       Size;  
  UINT64      AttributesSupported;  
  UINT64      AttributesSetting;  
  UINT64      Compatibilities;  
  UINT32      LowestSupportedImageVersion;  
  UINT32      LastAttemptVersion;
  UINT32      LastAttemptStatus; 
  UINT64                    HardwareInstance;
  EFI_FIRMWARE_IMAGE_DEP    *Dependencies;
} EFI_FIRMWARE_IMAGE_DESCRIPTOR;

typedef
EFI_STATUS
(*EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE_INFO)(
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL       *This,
  UINTN                           *ImageInfoSize,
  EFI_FIRMWARE_IMAGE_DESCRIPTOR   *ImageInfo,
        UINT32                          *DescriptorVersion,
        UINT8                           *DescriptorCount,
        UINTN                           *DescriptorSize,
         UINT32                          *PackageVersion,
        CHAR16                          **PackageVersionName
  );


  typedef
EFI_STATUS
(*EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE)(
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL  *This,
  UINT8                             ImageIndex,
  void                             *Image,
  UINTN                        *ImageSize
  );


typedef
EFI_STATUS
(*EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS)(
  UINTN                          Completion
  );


  typedef
EFI_STATUS
(*EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_IMAGE)(
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL                 *This,
  UINT8                                            ImageIndex,
  void                                      *Image,
  UINTN                                            ImageSize,
  void                                       *VendorCode,
  EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS    Progress,
  CHAR16                                           **AbortReason
  );

typedef  struct _EFI_FIRMWARE_MANAGEMENT_PROTOCOL {
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE_INFO      GetImageInfo;
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GET_IMAGE           GetImage;
  EFI_FIRMWARE_MANAGEMENT_PROTOCOL_SET_IMAGE           SetImage;
  void         *CheckImage;
  void *    GetPackageInfo;
  void *    SetPackageInfo;
} EFI_FIRMWARE_MANAGEMENT_PROTOCOL;
