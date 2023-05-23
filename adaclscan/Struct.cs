using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace adaclscan
{
    internal class Struct
    {
        public enum NETLOGON_SECURE_CHANNEL_TYPE : int
        {
            NullSecureChannel = 0,
            MsvApSecureChannel = 1,
            WorkstationSecureChannel = 2,
            TrustedDnsDomainSecureChannel = 3,
            TrustedDomainSecureChannel = 4,
            UasServerSecureChannel = 5,
            ServerSecureChannel = 6
        }

        [StructLayout(LayoutKind.Explicit, Size = 516)]
        public struct NL_TRUST_PASSWORD
        {
            [FieldOffset(0)]
            public ushort Buffer;

            [FieldOffset(512)]
            public uint Length;
        }

        [StructLayout(LayoutKind.Explicit, Size = 12)]
        public struct NETLOGON_AUTHENTICATOR
        {
            [FieldOffset(0)]
            public NETLOGON_CREDENTIAL Credential;

            [FieldOffset(8)]
            public uint Timestamp;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct NETLOGON_CREDENTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] data;
        }

        public enum RESOURCE_SCOPE
        {
            RESOURCE_CONNECTED = 1,
            RESOURCE_GLOBALNET = 2,
            RESOURCE_REMEMBERED = 3,
            RESOURCE_RECENT = 4,
            RESOURCE_CONTEXT = 5
        }

        public enum RESOURCE_TYPE
        {
            RESOURCETYPE_ANY = 0,
            RESOURCETYPE_DISK = 1,
            RESOURCETYPE_PRINT = 2,
            RESOURCETYPE_RESERVED = 8,
        }

        public enum RESOURCE_USAGE
        {
            RESOURCEUSAGE_CONNECTABLE = 1,
            RESOURCEUSAGE_CONTAINER = 2,
            RESOURCEUSAGE_NOLOCALDEVICE = 4,
            RESOURCEUSAGE_SIBLING = 8,
            RESOURCEUSAGE_ATTACHED = 16,
            RESOURCEUSAGE_ALL = (RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER | RESOURCEUSAGE_ATTACHED),
        }

        public enum RESOURCE_DISPLAYTYPE
        {
            RESOURCEDISPLAYTYPE_GENERIC = 0,
            RESOURCEDISPLAYTYPE_DOMAIN = 1,
            RESOURCEDISPLAYTYPE_SERVER = 2,
            RESOURCEDISPLAYTYPE_SHARE = 3,
            RESOURCEDISPLAYTYPE_FILE = 4,
            RESOURCEDISPLAYTYPE_GROUP = 5,
            RESOURCEDISPLAYTYPE_NETWORK = 6,
            RESOURCEDISPLAYTYPE_ROOT = 7,
            RESOURCEDISPLAYTYPE_SHAREADMIN = 8,
            RESOURCEDISPLAYTYPE_DIRECTORY = 9,
            RESOURCEDISPLAYTYPE_TREE = 10,
            RESOURCEDISPLAYTYPE_NDSCONTAINER = 11
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct NETRESOURCE
        {
            public RESOURCE_SCOPE dwScope;
            public RESOURCE_TYPE dwType;
            public RESOURCE_DISPLAYTYPE dwDisplayType;
            public RESOURCE_USAGE dwUsage;

            [MarshalAs(UnmanagedType.LPStr)] public string lpLocalName;

            [MarshalAs(UnmanagedType.LPStr)] public string lpRemoteName;

            [MarshalAs(UnmanagedType.LPStr)] public string lpComment;

            [MarshalAs(UnmanagedType.LPStr)] public string lpProvider;
        }

        public enum NetJoinStatus
        {
            NetSetupUnknownStatus = 0,
            NetSetupUnjoined,
            NetSetupWorkgroupName,
            NetSetupDomainName
        }

        public const int MAX_PREFERRED_LENGTH = -1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SESSION_INFO_10
        {
            public static readonly int SIZE_OF = Marshal.SizeOf(typeof(SESSION_INFO_10));
            public string sesi10_cname;
            public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }
        public enum NERR
        {
            ERROR_MORE_DATA = 234,
            ERROR_SUCCESS = 0,
        }
        const int NERR_SUCCESS = 0;
        const int ERROR_MORE_DATA = 234;

        public const int ErrorSuccess = 0;

        public struct MODULEINFO
        {
            internal IntPtr lpBaseOfDll;
            internal uint SizeOfImage;
            internal IntPtr EntryPoint;
        }

        public enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi1_sid;
            public int lgrmi1_sidusage;
            public string lgrmi2_domainandname;
        }

        public static string SID_NAME(int i)
        {
            string sidusage = "";
            switch (i)
            {
                case 1:
                    sidusage = "SidTypeUser";
                    break;
                case 2:
                    sidusage = "SidTypeGroup";
                    break;
                case 3:
                    sidusage = "SidTypeDomain";
                    break;
                case 4:
                    sidusage = "SidTypeAlias";
                    break;
                case 5:
                    sidusage = "SidTypeWellKnownGroup";
                    break;
                case 6:
                    sidusage = "SidTypeDeletedAccount";
                    break;
                case 7:
                    sidusage = "SidTypeInvalid";
                    break;
                case 8:
                    sidusage = "SidTypeUnknown";
                    break;
                case 9:
                    sidusage = "SidTypeComputer";
                    break;
                case 10:
                    sidusage = "SidTypeLabel";
                    break;
                case 11:
                    sidusage = "SidTypeLogonSession";
                    break;
            }
            return sidusage;
        }

        public enum DS_DOMAIN_TRUST_TYPE : uint
        {
            InForest = 0x0001,
            DirectOutBound = 0x0002,
            TreeRoot = 0x0004,
            Primary = 0x0008,
            NativeMode = 0x0010,
            DirectInBound = 0x0020
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }

        [Flags]
        public enum TrustAttributes : uint
        {
            NonTransitive = 0x1,
            UplevelOnly = 0x2,
            FilterSids = 0x4,
            ForestTransitive = 0x8,
            CrossOrganization = 0x10,
            WithinForest = 0x20,
            TreatAsExternal = 0x40,
            TrustUsesRc4 = 0x80,
            TrustUsesAes = 0x100,
            CrossOrganizationNoTGTDelegation = 0x200,
            PIMTrust = 0x400,
            CrossOrganizationEnableTGTDelegation = 0x800
        }

        public enum TrustDirection
        {
            Disable = 0,
            InBound = 1,
            OutBound = 2,
            BiDirectional = 3
        }


        [Flags]
        public enum TrustType
        {
            TreeRoot = 0,
            ParentChild = 1,
            ShortCut = 2,
            External = 3,
            Forest = 4,
            Kerberos = 5,
            Unknown = 6
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        public struct SHARE_INFO_2
        {
            public string shi2_netname;
            public int shi2_type;
            public string shi2_remark;
            public int shi2_permissions;
            public int shi2_max_uses;
            public int shi2_current_uses;
            public string shi2_path;
            public string shi2_passwd;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct NETBIOS_HEADER
        {
            public uint MessageTypeAndSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_HEADER
        {
            public uint protocol;
            public byte command;
            public byte errorClass;
            public byte _reserved;
            public ushort errorCode;
            public byte flags;
            public ushort flags2;
            public ushort PIDHigh;
            public ulong SecurityFeatures;
            public ushort reserved;
            public ushort TID;
            public ushort PIDLow;
            public ushort UID;
            public ushort MID;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_SESSION_SETUP_ANDX_RESPONSE
        {
            public byte WordCount;
            public byte AndxCommand;
            public byte reserved;
            public ushort AndxOffset;
            public ushort action;
            public ushort ByteCount;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_SESSION_SETUP_ANDX_REQUEST
        {
            public byte WordCount;
            public byte AndxCommand;
            public byte reserved1;
            public ushort AndxOffset;
            public ushort MaxBuffer;
            public ushort MaxMpxCount;
            public ushort VcNumber;
            public uint SessionKey;
            public ushort OEMPasswordLen;
            public ushort UnicodePasswordLen;
            public uint Reserved2;
            public uint Capabilities;
            public ushort ByteCount;
            //SMB Data added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_NEGOTIATE_REQUEST
        {
            public byte WordCount;
            public ushort ByteCount;
            //Dialects are added manually
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_TRANSACTION_REQUEST
        {
            public byte WordCount;
            public ushort TotalParameterCount;
            public ushort TotalDataCount;
            public ushort MaxParameterCount;
            public ushort MaxDataCount;
            public byte MaxSetupCount;
            public byte Reserved;
            public ushort Flags;
            public uint Timeout;
            public ushort Reserved2;
            public ushort ParameterCount;
            public ushort ParameterOffset;
            public ushort DataCount;
            public ushort DataOffset;
            public byte SetupCount;
            public byte Reserved3;
            public ushort Function;
            public ushort FID;
            public ushort ByteCount;
            //TransactionName added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_TREE_CONNECT_ANDX_REQUEST
        {
            public byte WordCount;
            public byte AndXCommand;
            public byte AndXReserved;
            public ushort AndXOffset;
            public ushort Flags;
            public ushort PasswordLength;
            public ushort ByteCount;
            //SMBData added manually
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_ECHO_REQUEST
        {
            public byte WordCount;
            public ushort EchoSequenceNumber;
            public ushort ByteCount;
            //SMBData added manually
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_NT_TRANSACT_REQUEST
        {
            public byte WordCount;
            public byte MaxSetupCount;
            public ushort Reserved;
            public uint TotalParameterCount;
            public uint TotalDataCount;
            public uint MaxParameterCount;
            public uint MaxDataCount;
            public uint ParameterCount;
            public uint ParameterOffset;
            public uint DataCount;
            public uint DataOffset;
            public byte SetupCount;
            public ushort Function;
            public ushort Setup;
            public ushort ByteCount;
            //SMBData added manually
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct SMB_COM_TRANSACTION2_SECONDARY_REQUEST
        {
            public byte WordCount;
            public ushort TotalParameterCount;
            public ushort TotalDataCount;
            public ushort ParameterCount;
            public ushort ParameterOffset;
            public ushort ParameterDisplacement;
            public ushort DataCout;
            public ushort DataOffset;
            public ushort DataDisplacement;
            public ushort FID;
            public ushort ByteCount;
            //SMBData added manually
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            ProcessIsTerminating = 0xC000010A,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            InsufficientBuffer = 0x7a,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SEC_WINNT_AUTH_IDENTITY_W
        {
            public string User;
            public int UserLength;
            public string Domain;
            public int DomainLength;
            public string Password;
            public int PasswordLength;
            public int Flags; //2 Uni
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SECURITY_QOS
        {
            public uint Version;
            public uint Capabilities;
            public uint IdentityTracking;
            public uint ImpersonationType;
        };

        public const int RPC_C_AUTHN_NONE = 0;
        public const uint RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH = 0x1;
        public const uint RPC_C_IMP_LEVEL_DELEGATE = 0x4;

        public const int RPC_C_AUTHN_WINNT = 10;
        public const int RPC_C_AUTHN_GSS_NEGOTIATE = 9;
        public const int RPC_C_AUTHN_GSS_KERBEROS = 16;

        public const int SECPKG_ATTR_SESSION_KEY = 9;
        public const uint RPC_C_QOS_CAPABILITIES_IGNORE_DELEGATE_FAILURE = 0x8;

        public const int RPC_C_OPT_SECURITY_CALLBACK = 10;
        public const int RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        public static SecurityCallbackDelegate rpcSecurityCallbackDelegate;
        public delegate void SecurityCallbackDelegate(IntPtr context);
        [StructLayout(LayoutKind.Sequential)]
        public struct SecPkgContext_SessionKey
        {
            public uint SessionKeyLength;
            public IntPtr SessionKey;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        public struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr DispatchTable;  //PRPC_DISPATCH_TABLE
            public uint RpcProtseqEndpointCount;
            public IntPtr RpcProtseqEndpoint; //PRPC_PROTSEQ_ENDPOINT
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SEC_WINNT_AUTH_IDENTITY
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;
            public int UserLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;
            public int DomainLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Password;
            public int PasswordLength;
            public int Flags;
        };

        internal struct COMVERSION
        {
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }
        public struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.
        }

        public enum msPKICertificateNameFlag : uint
        {
            ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,
            ADD_EMAIL = 0x00000002,
            ADD_OBJ_GUID = 0x00000004,
            OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008,
            ADD_DIRECTORY_PATH = 0x00000100,
            ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,
            SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,
            SUBJECT_ALT_REQUIRE_SPN = 0x00800000,
            SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,
            SUBJECT_ALT_REQUIRE_UPN = 0x02000000,
            SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,
            SUBJECT_ALT_REQUIRE_DNS = 0x08000000,
            SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000,
            SUBJECT_REQUIRE_EMAIL = 0x20000000,
            SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,
            SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,
        }

        [Flags]
        public enum msPKIEnrollmentFlag : uint
        {
            NONE = 0x00000000,
            INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001,
            PEND_ALL_REQUESTS = 0x00000002,
            PUBLISH_TO_KRA_CONTAINER = 0x00000004,
            PUBLISH_TO_DS = 0x00000008,
            AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010,
            AUTO_ENROLLMENT = 0x00000020,
            CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80,
            PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
            USER_INTERACTION_REQUIRED = 0x00000100,
            ADD_TEMPLATE_NAME = 0x200,
            REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400,
            ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800,
            ADD_OCSP_NOCHECK = 0x00001000,
            ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000,
            NOREVOCATIONINFOINISSUEDCERTS = 0x00004000,
            INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000,
            ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000,
            ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000,
            SKIP_AUTO_RENEWAL = 0x00040000
        }

        public enum PkiCertificateAuthorityFlags : uint
        {
            NO_TEMPLATE_SUPPORT = 0x00000001,
            SUPPORTS_NT_AUTHENTICATION = 0x00000002,
            CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004,
            CA_SERVERTYPE_ADVANCED = 0x00000008,
        }
    }
}
