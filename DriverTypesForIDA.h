/*
Copy this structures into the LocalDB of IDAPro and then syncrhonize
*/

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY  *Flink;
  struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY {
  struct _SINGLE_LIST_ENTRY  *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef struct _SLIST_HEADER
{
     union
     {
          UINT64 Alignment;
          struct
          {
               SINGLE_LIST_ENTRY Next;
               WORD Depth;
               WORD Sequence;
          };
     };
} SLIST_HEADER, *PSLIST_HEADER;

typedef struct _GENERAL_LOOKASIDE
{
     union
     {
          SLIST_HEADER ListHead;
          SINGLE_LIST_ENTRY SingleListHead;
     };
     WORD Depth;
     WORD MaximumDepth;
     ULONG TotalAllocates;
     union
     {
          ULONG AllocateMisses;
          ULONG AllocateHits;
     };
     ULONG TotalFrees;
     union
     {
          ULONG FreeMisses;
          ULONG FreeHits;
     };
     POOL_TYPE Type;
     ULONG Tag;
     ULONG Size;
     union
     {
          PVOID * AllocateEx;
          PVOID * Allocate;
     };
     union
     {
          PVOID FreeEx;
          PVOID Free;
     };
     LIST_ENTRY ListEntry;
     ULONG LastTotalAllocates;
     union
     {
          ULONG LastAllocateMisses;
          ULONG LastAllocateHits;
     };
     ULONG Future[2];
} GENERAL_LOOKASIDE, *PGENERAL_LOOKASIDE;

typedef struct LOOKASIDE_ALIGN_NPAGED_LOOKASIDE_LIST {
    GENERAL_LOOKASIDE L;
    ULONG Lock__ObsoleteButDoNotDelete;
} NPAGED_LOOKASIDE_LIST, *PNPAGED_LOOKASIDE_LIST;

/////////////////////////////////////////////////////////////////////////

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _OSVERSIONINFOW {
  ULONG dwOSVersionInfoSize;
  ULONG dwMajorVersion;
  ULONG dwMinorVersion;
  ULONG dwBuildNumber;
  ULONG dwPlatformId;
  WCHAR szCSDVersion[128];
} RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;


typedef enum _POOL_TYPE { 
  NonPagedPool,
  NonPagedPoolExecute                   = NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed               = NonPagedPool + 2,
  DontUseThisType,
  NonPagedPoolCacheAligned              = NonPagedPool + 4,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS         = NonPagedPool + 6,
  MaxPoolType,
  NonPagedPoolBase                      = 0,
  NonPagedPoolBaseMustSucceed           = NonPagedPoolBase + 2,
  NonPagedPoolBaseCacheAligned          = NonPagedPoolBase + 4,
  NonPagedPoolBaseCacheAlignedMustS     = NonPagedPoolBase + 6,
  NonPagedPoolSession                   = 32,
  PagedPoolSession                      = NonPagedPoolSession + 1,
  NonPagedPoolMustSucceedSession        = PagedPoolSession + 1,
  DontUseThisTypeSession                = NonPagedPoolMustSucceedSession + 1,
  NonPagedPoolCacheAlignedSession       = DontUseThisTypeSession + 1,
  PagedPoolCacheAlignedSession          = NonPagedPoolCacheAlignedSession + 1,
  NonPagedPoolCacheAlignedMustSSession  = PagedPoolCacheAlignedSession + 1,
  NonPagedPoolNx                        = 512,
  NonPagedPoolNxCacheAligned            = NonPagedPoolNx + 4,
  NonPagedPoolSessionNx                 = NonPagedPoolNx + 32
} POOL_TYPE;

typedef struct _FS_FILTER_CALLBACKS
{
     ULONG SizeOfFsFilterCallbacks;
     ULONG Reserved;
     LONG * PreAcquireForSectionSynchronization;
     PVOID PostAcquireForSectionSynchronization;
     LONG * PreReleaseForSectionSynchronization;
     PVOID PostReleaseForSectionSynchronization;
     LONG * PreAcquireForCcFlush;
     PVOID PostAcquireForCcFlush;
     LONG * PreReleaseForCcFlush;
     PVOID PostReleaseForCcFlush;
     LONG * PreAcquireForModifiedPageWriter;
     PVOID PostAcquireForModifiedPageWriter;
     LONG * PreReleaseForModifiedPageWriter;
     PVOID PostReleaseForModifiedPageWriter;
} FS_FILTER_CALLBACKS, *PFS_FILTER_CALLBACKS;

typedef struct _IO_CLIENT_EXTENSION
{
     struct _IO_CLIENT_EXTENSION *NextExtension;
     PVOID ClientIdentificationAddress;
} IO_CLIENT_EXTENSION, *PIO_CLIENT_EXTENSION;

typedef struct _DRIVER_EXTENSION
{
     PVOID DriverObject;
     LONG * AddDevice;
     ULONG Count;
     UNICODE_STRING ServiceKeyName;
     PIO_CLIENT_EXTENSION ClientDriverExtension;
     PFS_FILTER_CALLBACKS FsFilterCallbacks;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

typedef struct _FAST_IO_DISPATCH
{
     ULONG SizeOfFastIoDispatch;
     UCHAR * FastIoCheckIfPossible;
     UCHAR * FastIoRead;
     UCHAR * FastIoWrite;
     UCHAR * FastIoQueryBasicInfo;
     UCHAR * FastIoQueryStandardInfo;
     UCHAR * FastIoLock;
     UCHAR * FastIoUnlockSingle;
     UCHAR * FastIoUnlockAll;
     UCHAR * FastIoUnlockAllByKey;
     UCHAR * FastIoDeviceControl;
     PVOID AcquireFileForNtCreateSection;
     PVOID ReleaseFileForNtCreateSection;
     PVOID FastIoDetachDevice;
     UCHAR * FastIoQueryNetworkOpenInfo;
     LONG * AcquireForModWrite;
     UCHAR * MdlRead;
     UCHAR * MdlReadComplete;
     UCHAR * PrepareMdlWrite;
     UCHAR * MdlWriteComplete;
     UCHAR * FastIoReadCompressed;
     UCHAR * FastIoWriteCompressed;
     UCHAR * MdlReadCompleteCompressed;
     UCHAR * MdlWriteCompleteCompressed;
     UCHAR * FastIoQueryOpen;
     LONG * ReleaseForModWrite;
     LONG * AcquireForCcFlush;
     LONG * ReleaseForCcFlush;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

typedef struct _DRIVER_OBJECT
{
     SHORT Type;
     SHORT Size;
     PVOID DeviceObject;
     ULONG Flags;
     PVOID DriverStart;
     ULONG DriverSize;
     PVOID DriverSection;
     PDRIVER_EXTENSION DriverExtension;
     UNICODE_STRING DriverName;
     PUNICODE_STRING HardwareDatabase;
     PFAST_IO_DISPATCH FastIoDispatch;
     LONG * DriverInit;
     PVOID DriverStartIo;
     PVOID DriverUnload;
     LONG * MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef enum _DEVICE_POWER_STATE { 
  PowerDeviceUnspecified  = 0,
  PowerDeviceD0           = 1,
  PowerDeviceD1           = 2,
  PowerDeviceD2           = 3,
  PowerDeviceD3           = 4,
  PowerDeviceMaximum      = 5
} DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

typedef struct _POWER_CHANNEL_SUMMARY
{
     ULONG Signature;
     ULONG TotalCount;
     ULONG D0Count;
     LIST_ENTRY NotifyList;
} POWER_CHANNEL_SUMMARY, *PPOWER_CHANNEL_SUMMARY;

typedef struct _DEVICE_OBJECT_POWER_EXTENSION
{
     LONG IdleCount;
     ULONG ConservationIdleTime;
     ULONG PerformanceIdleTime;
     PVOID DeviceObject;
     LIST_ENTRY IdleList;
     UCHAR DeviceType;
     DEVICE_POWER_STATE State;
     LIST_ENTRY NotifySourceList;
     LIST_ENTRY NotifyTargetList;
     POWER_CHANNEL_SUMMARY PowerChannelSummary;
     LIST_ENTRY Volume;
     ULONG PreviousIdleCount;
} DEVICE_OBJECT_POWER_EXTENSION, *PDEVICE_OBJECT_POWER_EXTENSION;


typedef struct _VPB {
  CSHORT                Size;
  CSHORT                Type;
  USHORT                Flags;
  USHORT                VolumeLabelLength;
  struct _DEVICE_OBJECT  *DeviceObject;
  struct _DEVICE_OBJECT  *RealDevice;
  ULONG                 SerialNumber;
  ULONG                 ReferenceCount;
  WCHAR                 VolumeLabel[32];
} VPB, *PVPB;

typedef struct _DEVOBJ_EXTENSION
{
     SHORT Type;
     WORD Size;
     PVOID DeviceObject;
     ULONG PowerFlags;
     PDEVICE_OBJECT_POWER_EXTENSION Dope;
     ULONG ExtensionFlags;
     PVOID DeviceNode;
     PVOID AttachedTo;
     LONG StartIoCount;
     LONG StartIoKey;
     ULONG StartIoFlags;
     PVPB Vpb;
} DEVOBJ_EXTENSION, *PDEVOBJ_EXTENSION;

// MdlFlags
#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008
#define MDL_PARTIAL                 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ            0x0040
#define MDL_WRITE_OPERATION         0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA 0x0100
#define MDL_FREE_EXTRA_PTES         0x0200
#define MDL_DESCRIBES_AWE           0x0400
#define MDL_IO_SPACE                0x0800
#define MDL_NETWORK_HEADER          0x1000
#define MDL_MAPPING_CAN_FAIL        0x2000
#define MDL_ALLOCATED_MUST_SUCCEED  0x4000
#define MDL_INTERNAL                0x8000

typedef struct _MDL
{
     PMDL Next;
     SHORT Size;
     SHORT MdlFlags;
     PVOID Process;
     PVOID MappedSystemVa;
     PVOID StartVa;
     ULONG ByteCount;
     ULONG ByteOffset;
} MDL, *PMDL;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IRP
{
     SHORT Type;
     WORD Size;
     PMDL MdlAddress;
     ULONG Flags;
     ULONG SystemBuffer;
     LIST_ENTRY ThreadListEntry;
     IO_STATUS_BLOCK IoStatus;
     CHAR RequestorMode;
     UCHAR PendingReturned;
     CHAR StackCount;
     CHAR CurrentLocation;
     UCHAR Cancel;
     UCHAR CancelIrql;
     CHAR ApcEnvironment;
     UCHAR AllocationFlags;
     PIO_STATUS_BLOCK UserIosb;
     PVOID UserEvent;
     UINT64 Overlay;
     PVOID CancelRoutine;
     PVOID UserBuffer;
     ULONG Tail;
} IRP, *PIRP;


typedef struct _IO_TIMER
{
     SHORT Type;
     SHORT TimerFlag;
     LIST_ENTRY TimerList;
     PVOID TimerRoutine;
     PVOID Context;
     PVOID DeviceObject;
} IO_TIMER, *PIO_TIMER;

typedef struct _KDEVICE_QUEUE_ENTRY
{
     LIST_ENTRY DeviceListEntry;
     ULONG SortKey;
     UCHAR Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY;

typedef enum _IO_ALLOCATION_ACTION { 
  KeepObject                     = 1,
  DeallocateObject               = 2,
  DeallocateObjectKeepRegisters  = 3
} IO_ALLOCATION_ACTION, *PIO_ALLOCATION_ACTION;

typedef struct _DISPATCHER_HEADER
{
     union
     {
          struct
          {
               UCHAR Type;
               union
               {
                    UCHAR Abandoned;
                    UCHAR Absolute;
                    UCHAR NpxIrql;
                    UCHAR Signalling;
               };
               union
               {
                    UCHAR Size;
                    UCHAR Hand;
               };
               union
               {
                    UCHAR Inserted;
                    UCHAR DebugActive;
                    UCHAR DpcActive;
               };
          };
          LONG Lock;
     };
     LONG SignalState;
     LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef union _ULARGE_INTEGER {
  struct {
    DWORD LowPart;
    DWORD HighPart;
  };
  struct {
    DWORD LowPart;
    DWORD HighPart;
  } u;
  ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;


typedef struct _KTIMER
{
     DISPATCHER_HEADER Header;
     ULARGE_INTEGER DueTime;
     LIST_ENTRY TimerListEntry;
     PKDPC Dpc;
     LONG Period;
} KTIMER, *PKTIMER;

typedef struct _KDPC
{
     UCHAR Type;
     UCHAR Importance;
     WORD Number;
     LIST_ENTRY DpcListEntry;
     PVOID DeferredRoutine;
     PVOID DeferredContext;
     PVOID SystemArgument1;
     PVOID SystemArgument2;
     PVOID DpcData;
} KDPC, *PKDPC;

typedef struct _WAIT_CONTEXT_BLOCK
{
     KDEVICE_QUEUE_ENTRY WaitQueueEntry;
     PIO_ALLOCATION_ACTION DeviceRoutine;
     PVOID DeviceContext;
     ULONG NumberOfMapRegisters;
     PVOID DeviceObject;
     PVOID CurrentIrp;
     PKDPC BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, *PWAIT_CONTEXT_BLOCK;

typedef struct _KDEVICE_QUEUE
{
     SHORT Type;
     SHORT Size;
     LIST_ENTRY DeviceListHead;
     ULONG Lock;
     UCHAR Busy;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE;

typedef struct _DEVICE_OBJECT {
  CSHORT                      Type;
  USHORT                      Size;
  LONG                        ReferenceCount;
  struct _DRIVER_OBJECT  *DriverObject;
  struct _DEVICE_OBJECT  *NextDevice;
  struct _DEVICE_OBJECT  *AttachedDevice;
  struct _IRP  *CurrentIrp;
  PIO_TIMER                   Timer;
  ULONG                       Flags;
  ULONG                       Characteristics;
  PVPB             Vpb;
  PVOID                       DeviceExtension;
  LONG                 DeviceType;
  CCHAR                       StackSize;
  union {
    LIST_ENTRY         ListEntry;
    WAIT_CONTEXT_BLOCK Wcb;
  } Queue;
  ULONG                       AlignmentRequirement;
  KDEVICE_QUEUE               DeviceQueue;
  KDPC                        Dpc;
  ULONG                       ActiveThreadCount;
  PVOID        SecurityDescriptor;
  KEVENT                      DeviceLock;
  USHORT                      SectorSize;
  USHORT                      Spare1;
  struct _DEVOBJ_EXTENSION  *  DeviceObjectExtension;
  PVOID                       Reserved;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

///////////////////////////////////////////////////////////////////////

typedef enum _SECURITY_IMPERSONATION_LEVEL { 
  SecurityAnonymous,
  SecurityIdentification,
  SecurityImpersonation,
  SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;


// FIND THE DEFINITION OF ACCESS_TOKEN
typedef struct _SECURITY_SUBJECT_CONTEXT {
  PACCESS_TOKEN  ClientToken;
  SECURITY_IMPERSONATION_LEVEL  ImpersonationLevel;
  PACCESS_TOKEN  PrimaryToken;
  PVOID  ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;


/////////////////////////////////////////////////////////////////////////

typedef struct _KEVENT
{
     DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT;

/////////////////////////////////////////////////////////////////////////

typedef NDIS_STRING UNICODE_STRING;
typedef PNDIS_STRING PUNICODE_STRING;

typedef struct _NDIS_OBJECT_HEADER {
  UCHAR  Type;
  UCHAR  Revision;
  USHORT Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;


/////////////////////////////////////////////////////////////////////////

ULONG NET_BUFFER_DATA_LENGTH(
   PNET_BUFFER _NB
);

typedef struct _NET_BUFFER_DATA {
  PNET_BUFFER            Next;
  PMDL                   CurrentMdl;
  ULONG                  CurrentMdlOffset;
  NET_BUFFER_DATA_LENGTH NbDataLength;
  PMDL                   MdlChain;
  ULONG                  DataOffset;
} NET_BUFFER_DATA, *PNET_BUFFER_DATA;

typedef union _NET_BUFFER_HEADER {
  NET_BUFFER_DATA NetBufferData;
  SLIST_HEADER    Link;
} NET_BUFFER_HEADER, *PNET_BUFFER_HEADER;

typedef struct _NET_BUFFER {
  NET_BUFFER_HEADER     NetBufferHeader;
  USHORT                ChecksumBias;
  USHORT                Reserved;
  NDIS_HANDLE           NdisPoolHandle;
  PVOID                 NdisReserved[2];
  PVOID                 ProtocolReserved[6];
  PVOID                 MiniportReserved[4];
  NDIS_PHYSICAL_ADDRESS DataPhysicalAddress;
//#if (NDIS_SUPPORT_NDIS620)
//  union {
//    PNET_BUFFER_SHARED_MEMORY SharedMemoryInfo;
//    PSCATTER_GATHER_LIST      ScatterGatherList;
//  };
//#endif 
} NET_BUFFER, *PNET_BUFFER;

typedef struct _NET_BUFFER_LIST_DATA {
  PNET_BUFFER_LIST Next;
  PNET_BUFFER      FirstNetBuffer;
} NET_BUFFER_LIST_DATA, *PNET_BUFFER_LIST_DATA;

typedef union _NET_BUFFER_LIST_HEADER {
  NET_BUFFER_LIST_DATA NetBufferListData;
  SLIST_HEADER         Link;
} NET_BUFFER_LIST_HEADER, *PNET_BUFFER_LIST_HEADER;

typedef struct _NET_BUFFER_LIST_CONTEXT {
  PNET_BUFFER_LIST_CONTEXT Next;
  USHORT                   Size;
  USHORT                   Offset;
  UCHAR                    ContextData[];
} NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

typedef struct _NET_BUFFER_LIST {
  NET_BUFFER_LIST_HEADER   NetBufferListHeader;
  PNET_BUFFER_LIST_CONTEXT Context;
  PNET_BUFFER_LIST         ParentNetBufferList;
  NDIS_HANDLE              NdisPoolHandle;
  PVOID                    NdisReserved[2];
  PVOID                    ProtocolReserved[4];
  PVOID                    MiniportReserved[2];
  PVOID                    Scratch;
  NDIS_HANDLE              SourceHandle;
  ULONG                    NblFlags;
  LONG                     ChildRefCount;
  ULONG                    Flags;
  NDIS_STATUS              Status;
  PVOID                    NetBufferListInfo[MaxNetBufferListInfo];
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;


typedef struct _RTL_BALANCED_LINKS {
 struct _RTL_BALANCED_LINKS *Parent;
 struct _RTL_BALANCED_LINKS *LeftChild;
 struct _RTL_BALANCED_LINKS *RightChild;
 char Balance;
 char Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef enum _RTL_GENERIC_COMPARE_RESULTS {
  GenericLessThan,
  GenericGreaterThan,
  GenericEqual
} RTL_GENERIC_COMPARE_RESULTS, *PRTL_GENERIC_COMPARE_RESULTS;

typedef struct _RTL_AVL_TABLE {
 RTL_GENERIC_COMPARE_RESULTS BalancedRoot;
 PVOID OrderedPointer;
 int WhichOrderedElement;
 int NumberGenericTableElements;
 int DepthOfTree;
 PRTL_BALANCED_LINKS RestartKey;
 int DeleteCount;
 PVOID CompareRoutine;
 PVOID AllocateRoutine;
 PVOID FreeRoutine;
 PVOID TableContext; 
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;



typedef struct _NET_LUID_LH {
 ULONG64 Value;
} NET_LUID_LH, PNET_LUID_LH;

typedef struct _NET_LUID {
 ULONG64 Value;
} NET_LUID, PNET_LUID;

typedef enum _NET_IF_MEDIA_CONNECT_STATE {
  MediaConnectStateUnknown,
  MediaConnectStateConnected,
  MediaConnectStateDisconnected
} NET_IF_MEDIA_CONNECT_STATE, *PNET_IF_MEDIA_CONNECT_STATE;

typedef enum _NET_IF_MEDIA_DUPLEX_STATE {
  MediaDuplexStateUnknown,
  MediaDuplexStateHalf,
  MediaDuplexStateFull
} NET_IF_MEDIA_DUPLEX_STATE, *PNET_IF_MEDIA_DUPLEX_STATE;


typedef enum _NDIS_MEDIUM { 
  NdisMedium802_3,
  NdisMedium802_5,
  NdisMediumFddi,
  NdisMediumWan,
  NdisMediumLocalTalk,
  NdisMediumDix,
  NdisMediumArcnetRaw,
  NdisMediumArcnet878_2,
  NdisMediumAtm,
  NdisMediumWirelessWan,
  NdisMediumIrda,
  NdisMediumBpc,
  NdisMediumCoWan,
  NdisMedium1394,
  NdisMediumInfiniBand,
  NdisMediumTunnel,
  NdisMediumNative802_11,
  NdisMediumLoopback,
  NdisMediumIP,
  NdisMediumMax
} NDIS_MEDIUM, *PNDIS_MEDIUM;

typedef enum _NDIS_PHYSICAL_MEDIUM
{
    NdisPhysicalMediumUnspecified,
    NdisPhysicalMediumWirelessLan,
    NdisPhysicalMediumCableModem,
    NdisPhysicalMediumPhoneLine,
    NdisPhysicalMediumPowerLine,
    NdisPhysicalMediumDSL,      
    NdisPhysicalMediumFibreChannel,
    NdisPhysicalMedium1394,
    NdisPhysicalMediumWirelessWan,
    NdisPhysicalMediumNative802_11,
    NdisPhysicalMediumBluetooth,
    NdisPhysicalMediumMax      
} NDIS_PHYSICAL_MEDIUM, *PNDIS_PHYSICAL_MEDIUM;

typedef struct _NDIS_GENERIC_OBJECT {
  NDIS_OBJECT_HEADER Header;
  PVOID              Caller;
  PVOID              CallersCaller;
  PDRIVER_OBJECT     DriverObject;
} NDIS_GENERIC_OBJECT, *PNDIS_GENERIC_OBJECT;

typedef struct _NET_LUID {
 ULONG64 Value;
} NET_LUID, PNET_LUID;

typedef struct _NDIS_FILTER_ATTACH_PARAMETERS {
  NDIS_OBJECT_HEADER		    Header;
  int             		    IfIndex;
  NET_LUID  			    NetLuid;
  int            		    FilterModuleGuidName;
  int 				    BaseMiniportIfIndex;
  PNDIS_STRING 			    BaseMiniportInstanceName;
  PNDIS_STRING                      BaseMiniportName;
  NET_IF_MEDIA_CONNECT_STATE        MediaConnectState;
  NET_IF_MEDIA_DUPLEX_STATE         MediaDuplexState;
  ULONG64                           XmitLinkSpeed;
  ULONG64                           RcvLinkSpeed;
  NDIS_MEDIUM                       MiniportMediaType;
  NDIS_PHYSICAL_MEDIUM              MiniportPhysicalMediaType;
  NDIS_HANDLE                       MiniportMediaSpecificAttributes;
  PVOID                     	    DefaultOffloadConfiguration;
  USHORT                            MacAddressLength;
  UCHAR                             CurrentMacAddress[32];
  NET_LUID                          BaseMiniportNetLuid;
  int                               LowerIfIndex;
  NET_LUID                          LowerIfNetLuid;
  ULONG                             Flags;
  PVOID     			    HDSplitCurrentConfig;
  PVOID     		   	    ReceiveFilterCapabilities;
  PVOID     			    MiniportPhysicalDeviceObject;
  PVOID     			    NicSwitchCapabilities;	
} NDIS_FILTER_ATTACH_PARAMETERS, *PNDIS_FILTER_ATTACH_PARAMETERS;

struct _NDIS_FILTER_DRIVER_CHARACTERISTICS
{
  NDIS_OBJECT_HEADER Header;
  UCHAR MajorNdisVersion;
  UCHAR MinorNdisVersion;
  UCHAR MajorDriverVersion;
  UCHAR MinorDriverVersion;
  ULONG Flags;
  NDIS_STRING FriendlyName;
  NDIS_STRING UniqueName;
  NDIS_STRING ServiceName;
  PVOID SetOptionsHandler;
  PVOID SetFilterModuleOptionsHandler;
  PVOID AttachHandler;
  PVOID DetachHandler;
  PVOID RestartHandler;
  PVOID PauseHandler;
  PVOID SendNetBufferListsHandler;
  PVOID SendNetBufferListsCompleteHandler;
  PVOID CancelSendNetBufferListsHandler;
  PVOID ReceiveNetBufferListsHandler;
  PVOID ReturnNetBufferListsHandler;
  PVOID OidRequestHandler;
  PVOID OidRequestCompleteHandler;
  PVOID CancelOidRequestHandler;
  PVOID DevicePnPEventNotifyHandler;
  PVOID NetPnPEventHandler;
  PVOID StatusHandler;
};


typedef struct _WDF_VERSION_INFO {
  ULONG Size;
  PWSTR LibraryName;
  ULONG WdfMajorVersion;
  ULONG WdfMinorVersion;
  ULONG WdfBuildNumber;
  ULONG NumWdfFunctions;
  PVOID WdfFunctions;
} WDF_VERSION_INFO, *PWDF_VERSION_INFO;



typedef struct _NET_BUFFER_LIST_POOL_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  UCHAR              ProtocolId;
  BOOLEAN            fAllocateNetBuffer;
  USHORT             ContextSize;
  ULONG              PoolTag;
  ULONG              DataSize;
} NET_BUFFER_LIST_POOL_PARAMETERS, *PNET_BUFFER_LIST_POOL_PARAMETERS;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;

typedef struct FWPS_CALLOUT0_ {
  GUID                                calloutKey;
  UINT32                              flags;
  PVOID           classifyFn;
  PVOID             notifyFn;
  PVOID flowDeleteFn;
} FWPS_CALLOUT0;

typedef struct FWPM_DISPLAY_DATA0_ {
  wchar_t *name;
  wchar_t *description;
} FWPM_DISPLAY_DATA0;

typedef struct FWP_BYTE_BLOB_ {
  UINT32 size;
  UINT8  *data;
} FWP_BYTE_BLOB;

typedef struct FWPM_CALLOUT0_ {
  GUID               calloutKey;
  FWPM_DISPLAY_DATA0 displayData;
  UINT32             flags;
  GUID               *providerKey;
  FWP_BYTE_BLOB      providerData;
  GUID               applicableLayer;
  UINT32             calloutId;
} FWPM_CALLOUT0;

typedef enum FWP_DATA_TYPE_ { 
  FWP_EMPTY,
  FWP_UINT8,
  FWP_UINT16,
  FWP_UINT32,
  FWP_UINT64,
  FWP_INT8,
  FWP_INT16,
  FWP_INT32,
  FWP_INT64,
  FWP_FLOAT,
  FWP_DOUBLE,
  FWP_BYTE_ARRAY16_TYPE,
  FWP_BYTE_BLOB_TYPE,
  FWP_SID,
  FWP_SECURITY_DESCRIPTOR_TYPE,
  FWP_TOKEN_INFORMATION_TYPE ,
  FWP_TOKEN_ACCESS_INFORMATION_TYPE ,
  FWP_UNICODE_STRING_TYPE,
  FWP_BYTE_ARRAY6_TYPE,
  FWP_SINGLE_DATA_TYPE_MAX            = 0xFF,
  FWP_V4_ADDR_MASK,
  FWP_V6_ADDR_MASK,
  FWP_RANGE_TYPE,
  FWP_DATA_TYPE_MAX
} FWP_DATA_TYPE;

typedef struct FWP_BYTE_ARRAY16_ {
  UINT8 byteArray16[16];
} FWP_BYTE_ARRAY16;

typedef struct _SID_AND_ATTRIBUTES {
  PVOID  Sid;
  DWORD Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct FWP_TOKEN_INFORMATION_ {
  ULONG               sidCount;
  PSID_AND_ATTRIBUTES sids;
  ULONG               restrictedSidCount;
  PSID_AND_ATTRIBUTES restrictedSids;
} FWP_TOKEN_INFORMATION;

typedef struct FWP_BYTE_ARRAY6_ {
  UINT8 byteArray6[6];
} FWP_BYTE_ARRAY6;

typedef struct FWP_VALUE0_ {
  FWP_DATA_TYPE type;
  union {   
    UINT8                 uint8;
    UINT16                uint16;
    UINT32                uint32;
    UINT64                *uint64;
    INT8                  int8;
    INT16                 int16;
    INT32                 int32;
    INT64                 *int64;
    float                 float32;
    double                *double64;
    FWP_BYTE_ARRAY16      *byteArray16;
    FWP_BYTE_BLOB         *byteBlob;
    PVOID                   *sid;
    FWP_BYTE_BLOB         *sd;
    FWP_TOKEN_INFORMATION *tokenInformation;
    FWP_BYTE_BLOB         *tokenAccessInformation;
    LPWSTR                unicodeString;
    FWP_BYTE_ARRAY6       *byteArray6;
  };
} FWP_VALUE0;

typedef enum FWP_MATCH_TYPE_ { 
  FWP_MATCH_EQUAL,
  FWP_MATCH_GREATER,
  FWP_MATCH_LESS,
  FWP_MATCH_GREATER_OR_EQUAL,
  FWP_MATCH_LESS_OR_EQUAL,
  FWP_MATCH_RANGE,
  FWP_MATCH_FLAGS_ALL_SET,
  FWP_MATCH_FLAGS_ANY_SET,
  FWP_MATCH_FLAGS_NONE_SET,
  FWP_MATCH_EQUAL_CASE_INSENSITIVE,
  FWP_MATCH_NOT_EQUAL,
  FWP_MATCH_TYPE_MAX
} FWP_MATCH_TYPE;

typedef struct FWP_V4_ADDR_AND_MASK_ {
  UINT32 addr;
  UINT32 mask;
} FWP_V4_ADDR_AND_MASK;

typedef struct FWP_V6_ADDR_AND_MASK_ {
  UINT8 addr[16];
  UINT8 prefixLength;
} FWP_V6_ADDR_AND_MASK;

typedef struct FWP_RANGE0_ {
  FWP_VALUE0 valueLow;
  FWP_VALUE0 valueHigh;
} FWP_RANGE0;


typedef struct FWP_CONDITION_VALUE0_ {
  FWP_DATA_TYPE type;
  union {
    UINT8                 uint8;
    UINT16                uint16;
    UINT32                uint32;
    UINT64                *uint64;
    INT8                  int8;
    INT16                 int16;
    INT32                 int32;
    INT64                 *int64;
    float                 float32;
    double                *double64;
    FWP_BYTE_ARRAY16      *byteArray16;
    FWP_BYTE_BLOB         *byteBlob;
    PVOID                   *sid;
    FWP_BYTE_BLOB         *sd;
    FWP_TOKEN_INFORMATION *tokenInformation;
    FWP_BYTE_BLOB         *tokenAccessInformation;
    LPWSTR                unicodeString;
    FWP_BYTE_ARRAY6       *byteArray6;
    FWP_V4_ADDR_AND_MASK  *v4AddrMask;
    FWP_V6_ADDR_AND_MASK  *v6AddrMask;
    FWP_RANGE0            *rangeValue;
  };
} FWP_CONDITION_VALUE0;

typedef struct FWPM_FILTER_CONDITION0_ {
  GUID                fieldKey;
  FWP_MATCH_TYPE      matchType;
  FWP_CONDITION_VALUE0 conditionValue;
} FWPM_FILTER_CONDITION0;

typedef UINT32 FWP_ACTION_TYPE;

typedef struct FWPM_ACTION0_ {
  FWP_ACTION_TYPE type;
  union {
    GUID filterType;
    GUID calloutKey;
  };
} FWPM_ACTION0;

typedef struct FWPM_FILTER0_ {
  GUID                   filterKey;
  FWPM_DISPLAY_DATA0     displayData;
  UINT32                 flags;
  GUID                   *providerKey;
  FWP_BYTE_BLOB          providerData;
  GUID                   layerKey;
  GUID                   subLayerKey;
  FWP_VALUE0             weight;
  UINT32                 numFilterConditions;
  FWPM_FILTER_CONDITION0 *filterCondition;
  FWPM_ACTION0           action;
  union {
    UINT64 rawContext;
    GUID   providerContextKey;
  };
  GUID                   *reserved;
  UINT64                 filterId;
  FWP_VALUE0             effectiveWeight;
} FWPM_FILTER0;

//https://chromium.googlesource.com/chromium/deps/perl/+/master/c/i686-w64-mingw32/include/fwptypes.h
