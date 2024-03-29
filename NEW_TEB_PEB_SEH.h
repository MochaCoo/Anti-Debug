#pragma once
#include <Windows.h>
#include <winternl.h>
namespace tps {
/*
typedef struct _NT_TIB {//sizeof x86:7*4 x64:7*8
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;//&fs:[0] x86下指向SEH链(可能存在safeSEH机制),x64下表式静态存储SEH在Exception Directory(异常表)
    PVOID StackBase;//&fs:[4h] 线程堆栈栈顶
    PVOID StackLimit;//&fs:[8h] 线程堆栈栈底
    PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        PVOID FiberData;
        DWORD Version;
    };
#else
    PVOID FiberData;//线程的纤程
#endif
    PVOID ArbitraryUserPointer;//任意用户指针
    struct _NT_TIB *Self;//&fs:[0]=fs:[0x18] &gs:[0]=gs:[0x30]//TEB ntdll.NtCurrentTeb()
} NT_TIB,*PNT_TIB;
*/

//https://www.cnblogs.com/lanrenxinxin/p/4631836.html
//TEB->PEB->PPEB_LDR_DATA->PLDR_DATA_TABLE_ENTRY

/* SEH SEH链表结构 _EXCEPTION_RECORD结构体(CONTEXT结构体) Handler函数指针 Handler函数返回值 __try__except回调函数参数 __try__except回调函数返回值
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;//(位于链表末尾时为0xffffffff)栈溢出覆盖seh时 jmp六个字节(2字节nop+下面注释描述的精心构造的Handler)(eb 06 90 90)执行栈中shellcode
    PEXCEPTION_ROUTINE Handler;//指向[含有pop(弹出返回地址)+pop(弹出_EXCEPTION_RECORD *)+ret(到EstablisherFrame指向的_EXCEPTION_REGISTRATION_RECORD结构并执行其中的Next成员(在栈上)的jmp指令)]的地址(不可在栈上)(或同理故意构造的栈不平衡,偏移地址使得调用函数时少push几个参数)
} EXCEPTION_REGISTRATION_RECORD;

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;          //异常码,说明异常类型,以STATUS_或EXCEPTION_开头，可自定义(sehdef.inc)
    DWORD ExceptionFlags;            //异常标志。0可修复；1不可修复(继续执行会返回EXCEPTION_NONCONTINUABLE_EXCEPTION异常)；2正在展开，不要试图修复(unwind)
    struct _EXCEPTION_RECORD *ExceptionRecord; //指向嵌套的异常结构，通常是异常中又引发异常
    PVOID ExceptionAddress;          //异常发生的地址
    DWORD NumberParameters;      //下面ExceptionInformation成员数,不超过EXCEPTION_MAXIMUM_PARAMETERS=15
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS]; //异常附加数据,可以通过RaiseException自定义
} EXCEPTION_RECORD;

void RaiseException(//用来产生一个程序自定义异常
  [in] DWORD           dwExceptionCode,//指定_EXCEPTION_RECORD.ExceptionCode,传递给异常处理之前,系统会将ExceptionCode的第28位(从零开始算)置0,此位是保留的异常位
  [in] DWORD           dwExceptionFlags,//指定_EXCEPTION_RECORD.ExceptionFlags,为零指示可修复的异常,EXCEPTION_NONCONTINUABLE=1指示不可修复的异常
  [in] DWORD           nNumberOfArguments,//指定_EXCEPTION_RECORD.NumberParameters,此值不得超过EXCEPTION_MAXIMUM_PARAMETERS,如果lpArguments为NULL,则此参数置0
  [in] const ULONG_PTR *lpArguments//指定_EXCEPTION_RECORD.ExceptionInformation
);

typedef
_IRQL_requires_same_
_Function_class_(EXCEPTION_ROUTINE)
EXCEPTION_DISPOSITION//枚举类型
NTAPI//__stdcall
EXCEPTION_ROUTINE (//直接在SEH异常注册的函数的结构
    _Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,//=PEXCEPTION_RECORD 指向包含异常信息的EXCEPTION_RECORD结构
    _In_ PVOID EstablisherFrame,//x86:指向该异常相关的EXCEPTION_REGISTRATION(同_EXCEPTION_REGISTRATION_RECORD)结构 里面的Handler存储的就是当前函数指针 x64:某个使用了SEH的函数在try块中发生异常,此参数=此函数发生异常执前行完prolog后的rsp
    _Inout_ struct _CONTEXT *ContextRecord,//=PCONTEXT 指向线程环境CONTEXT结构的指针,使用Set/GetThreadContext时先设置字段CONTEXT.ContextFlags(Context_...)指明要获取的寄存器的值
    _In_ PVOID DispatcherContext//未知用途
    );

typedef enum _EXCEPTION_DISPOSITION {//EXCEPTION_ROUTINE函数返回值
    ExceptionContinueExecution,//继续执行异常代码
    ExceptionContinueSearch,//运行下一个异常处理器
    ExceptionNestedException,//在OS内部使用,从指定的新异常继续遍历
    ExceptionCollidedUnwind//在OS内部使用,在展开过程中再次触发异常
} EXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_POINTERS {//GetExceptionInformation()返回值//本质:Microsoft C/C++编译器将此函数解释为关键字
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;//同struct _CONTEXT *ContextRecord
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

//SEH异常筛选器返回值含义
#define EXCEPTION_EXECUTE_HANDLER       1 //表示异常被处理,会先把内部的__finally块(不管try中是否异常都会执行)执行完,再跳到自身的__except块中执行
#define EXCEPTION_CONTINUE_SEARCH       0 //表示异常未被处理，异常交给下一个SEH处理
#define EXCEPTION_CONTINUE_EXECUTION    -1 //表示异常被处理,从异常指令开始执行(不执行__except块中的内容),如果该条异常指令不被修正，则会再次产生一个异常
*/
#pragma pack(push, 1)
    template <typename PTR>
    struct _UNICODE_STRING//x86:0x8 x64:0x10(结构体对齐)
    {
        union
        {
            struct
            {
                WORD Length;//UNICODE占用的内存字节数,字符个数*2
                WORD MaximumLength;//Length+2字节,即包括终止符长度
            };
            PTR dummy;
        };
        PTR Buffer;
    };
    typedef _UNICODE_STRING<wchar_t*> UNICODE_STRING, * PUNICODE_STRING;

    template <class T>
    struct _LDR_DATA_TABLE_ENTRY_T
    {
        LIST_ENTRY InLoadOrderLinks;//模块加载顺序
        LIST_ENTRY InMemoryOrderLinks;//模块在内存中的顺序
        LIST_ENTRY InInitializationOrderLinks;//模块初始化装载顺序
        T DllBase;
        T EntryPoint;
        union
        {
            DWORD SizeOfImage;
            T dummy01;
        };
        UNICODE_STRING FullDllName;//0x24 模块路径 有关API:GetModuleFileName/GetModuleHandle 调用GetModuleHandle只提供文件名且进程中有多个同名不同路径模块时,返回第一个匹配的模块基址
        UNICODE_STRING BaseDllName;//0x2C 保留 模块文件名 某些时候为-1
        DWORD Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                T SectionPointer;
                T CheckSum;
            };
        };
        union
        {
            T LoadedImports;
            DWORD TimeDateStamp;
        };
        T EntryPointActivationContext;//_ACTIVATION_CONTEXT*
        T PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
        T ContextInformation;
        T OriginalBase;
        _LARGE_INTEGER LoadTime;
    };

    template <class T>
    struct _PEB_LDR_DATA_T
    {
        DWORD Length;//结构体大小
        DWORD Initialized;//进程是否初始化完成
        T SsHandle;
        LIST_ENTRY InLoadOrderModuleList;//0xC 模块加载顺序 (Flink).exe->ntdll.dll->kernel32.dll->kernelbase.dll->DllBase=00000000(Blink) 双向链表 指向_LDR_DATA_TABLE_ENTRY中的InLoadOrderLinks
        LIST_ENTRY InMemoryOrderModuleList;//0x14 模块在内存中的顺序(除exe由高到低) (Flink).exe->ntdll.dll->kernel32.dll->kernelbase.dll->DllBase=00000000(Blink) 双向链表 指向_LDR_DATA_TABLE_ENTRY中的InMemoryOrderLinks
        LIST_ENTRY InInitializationOrderModuleList;//0x1C 模块初始化装载顺序(不同系统顺序不一样) (Flink)ntdll.dll->kernelbase.dll->kernel32.dll->DllBase=00000000(Blink) 双向链表 指向_LDR_DATA_TABLE_ENTRY中的InInitializationOrderOrderLinks
        T EntryInProgress;
        DWORD ShutdownInProgress;
        T ShutdownThreadId;
    };

    template<typename PTR>
    struct CURDIR {
        UNICODE_STRING DosPath;
        PTR Handle;
    };

    template<typename PTR>
    struct _RTL_USER_PROCESS_PARAMETERS_T {//进程参数
        ULONG MaximumLength;
        ULONG Length;

        ULONG Flags;
        ULONG DebugFlags;

        PTR ConsoleHandle;
        ULONG  ConsoleFlags;
        PTR StandardInput;
        PTR StandardOutput;
        PTR StandardError;

        CURDIR<PTR> CurrentDirectory;//x86:0x28运行目录
        UNICODE_STRING DllPath;
        UNICODE_STRING ImagePathName;//x86:0x38 x64:0x60 PWSTR:x86:0x3C->进程路径 x64:0x68->进程路径
        UNICODE_STRING CommandLine;//x86:0x40 x64:0x70 PWSTR:x86:0x44->命令行 x64:0x78->命令行
        PTR Environment;

        //反调试检测用
        ULONG StartingX;//_STARTUPINFOA.dwX
        ULONG StartingY;//_STARTUPINFOA.dwY
        ULONG CountX;//_STARTUPINFOA.dwXSize
        ULONG CountY;//_STARTUPINFOA.dwYSize
        ULONG CountCharsX;//_STARTUPINFOA.dwXCountChars
        ULONG CountCharsY;//_STARTUPINFOA.dwYCountChars
        ULONG FillAttribute;//_STARTUPINFOA.dwFillAttribute

        ULONG WindowFlags;//_STARTUPINFOA.dwFlags (explorer.exe创建的进程此参数 = STARTF_USESHOWWINDOW)
        ULONG ShowWindowFlags;//_STARTUPINFOA.wShowWindow (explorer.exe创建的进程此参数 = SW_SHOWNORMAL)
        UNICODE_STRING WindowTitle;
        UNICODE_STRING DesktopInfo;
        UNICODE_STRING ShellInfo;
        UNICODE_STRING RuntimeData;
    };

    template <typename T, typename NGF, typename PLDRDATA, typename TProcessParameters, int A>
    struct _PEB_T//使用CreateProcessA(CREATE_SUSPENDED)时,系统此时还未填充IAT;GetThreadContext()->ebx指向PEB结构(进程环境块);->eax储存入口点地址;->eip指向ntdll.RtlUserThreadStart()
    {
        union
        {
            struct
            {
                BYTE InheritedAddressSpace;
                BYTE ReadImageFileExecOptions;
                BYTE BeingDebugged;//IsDebuggerPresent() Debug=true
                BYTE _SYSTEM_DEPENDENT_01;
            };
            T dummy01;//x64下注意结构体对齐
        };
        T Mutant;
        T ImageBaseAddress;//GetModuleHandle(0) PE中的IMAGE_OPTIONAL_HEADER.ImageBase
        PLDRDATA* Ldr;// 0Ch PPEB_LDR_DATA
        TProcessParameters* ProcessParameters;// x86:10h x64:20(结构体对齐) PRTL_USER_PROCESS_PARAMETERS 进程参数
        T SubSystemData;
        T ProcessHeap;// 18h 进程初始化时由RtlCreateHeap()创建 GetProcessHeap()返回的就是这个成员的值 进程(默认)堆的句柄实际上就是这个堆的起始地址,里面首先保存了HEAP结构体 https://mp.weixin.qq.com/s/cdvMp65C7tBC2e8-pwiJpA
                      //HeapCreate内部主要调用RtlCreateHeap函数，因此私有堆和默认堆并没有本质的差异，只是创建的用途不同,RtlCreateHeap内部会调用ZwAllocateMemory系统服务从内存管理器申请内存空间，初始化用于维护堆的数据结构，最后将堆句柄记录到进程的PEB结构的堆列表中
                      //与其他函数创建的对象保存在内核空间中不同，应用程序创建的堆是在用户空间保存的
                      //HeapDestroy主要调用NTDLL中的RtlDestoryHeap函数。后者会从PEB的堆列表中将要销毁的堆句柄移除，然后调用NtFreeVirtualMemory向内存管理器归还内存
        T FastPebLock;
        T _SYSTEM_DEPENDENT_02;//部分系统: PVOID FastPebLockRoutine; // 20h PPEBLOCKROUTINE RtlEnterCriticalSection的指针
        T _SYSTEM_DEPENDENT_03;//部分系统: PVOID FastPebUnlockRoutine; // 24h PPEBUNLOCKROUTINE RtlLeaveCriticalSection的指针
        T _SYSTEM_DEPENDENT_04;
        union
        {
            T KernelCallbackTable;
            T UserSharedInfoPtr;
        };
        DWORD SystemReserved;
        DWORD _SYSTEM_DEPENDENT_05;
        T _SYSTEM_DEPENDENT_06;
        T TlsExpansionCounter;
        T TlsBitmap;
        DWORD TlsBitmapBits[2];
        T ReadOnlySharedMemoryBase;
        T _SYSTEM_DEPENDENT_07;
        T ReadOnlyStaticServerData;
        T AnsiCodePageData;
        T OemCodePageData;
        T UnicodeCaseTableData;
        DWORD NumberOfProcessors;//可以用于获取CPU核心数
        union
        {
            DWORD NtGlobalFlag;
            NGF dummy02;
        };
        LARGE_INTEGER CriticalSectionTimeout;
        T HeapSegmentReserve;//堆的默认保留大小, 字节数
        T HeapSegmentCommit;//堆的默认提交大小,其默认值为两个内存页大小;x86系统中普通内存页的大小为4k,因此是0x2000,即8k
        T HeapDeCommitTotalFreeThreshold;
        T HeapDeCommitFreeBlockThreshold;
        DWORD NumberOfHeaps;//记录堆的总数
        DWORD MaximumNumberOfHeaps;//指定ProcessHeaps数组最大个数,当NumberOfHeaps达到该值的大小,那么堆管理器就会增大MaximumNumberOfHeaps的值,并重新分配ProcessHeaps数组
        T ProcessHeaps;//堆列表 记录每个堆的句柄,是一个数组,这个数组可以容纳的句柄数记录在MaximumNumberOfHeaps中
        T GdiSharedHandleTable;
        T ProcessStarterHelper;
        T GdiDCAttributeList;
        T LoaderLock;
        DWORD OSMajorVersion;
        DWORD OSMinorVersion;
        WORD OSBuildNumber;
        WORD OSCSDVersion;
        DWORD OSPlatformId;
        DWORD ImageSubsystem;
        DWORD ImageSubsystemMajorVersion;
        T ImageSubsystemMinorVersion;
        union
        {
            T ImageProcessAffinityMask;
            T ActiveProcessAffinityMask;
        };
        T GdiHandleBuffer[A];
        T PostProcessInitRoutine;
        T TlsExpansionBitmap;
        DWORD TlsExpansionBitmapBits[32];
        T SessionId;
        ULARGE_INTEGER AppCompatFlags;
        ULARGE_INTEGER AppCompatFlagsUser;
        T pShimData;
        T AppCompatInfo;
        UNICODE_STRING CSDVersion;
        T ActivationContextData;
        T ProcessAssemblyStorageMap;
        T SystemDefaultActivationContextData;
        T SystemAssemblyStorageMap;
        T MinimumStackCommit;
    };
#pragma pack(pop)

    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;
#ifdef _WIN64
    typedef LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#else
    typedef LDR_DATA_TABLE_ENTRY32 LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif

    typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
    typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;
#ifdef _WIN64
    typedef PEB_LDR_DATA64 PEB_LDR_DATA, * PPEB_LDR_DATA;
#else
    typedef PEB_LDR_DATA32 PEB_LDR_DATA, * PPEB_LDR_DATA;
#endif

    typedef _RTL_USER_PROCESS_PARAMETERS_T<ULONG_PTR> RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef _PEB_T<DWORD, DWORD64, PEB_LDR_DATA32, RTL_USER_PROCESS_PARAMETERS, 34> PEB32;
    typedef _PEB_T<DWORD64, DWORD, PEB_LDR_DATA64, RTL_USER_PROCESS_PARAMETERS, 30> PEB64;
#ifdef _WIN64
    typedef PEB64 PEB, * PPEB;
#else
    typedef PEB32 PEB, * PPEB;
#endif

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;//当前进程的的Pid
        HANDLE UniqueThread;//当前线程的的Tid
    } CLIENT_ID, * PCLIENT_ID;

    typedef struct _ACTIVATION_CONTEXT_STACK
    {
        struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
        LIST_ENTRY FrameListCache;
        ULONG Flags;
        ULONG NextCookieSequenceNumber;
        ULONG StackId;
    } ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

#define GDI_BATCH_BUFFER_SIZE 310
    typedef struct _GDI_TEB_BATCH
    {
        ULONG Offset;
        ULONG_PTR HDC;
        ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
    } GDI_TEB_BATCH, * PGDI_TEB_BATCH;

    typedef struct _TEB_ACTIVE_FRAME_CONTEXT
    {
        ULONG Flags;
        PSTR FrameName;
    } TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

    typedef struct _TEB_ACTIVE_FRAME
    {
        ULONG Flags;
        struct _TEB_ACTIVE_FRAME* Previous;
        PTEB_ACTIVE_FRAME_CONTEXT Context;
    } TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

    typedef struct _TEB//WOW64进程中的R12寄存器指向其64位的TEB结构(线程环境块)=切换到x64下的gs:[0x30] fs:[0x18]
    {
        NT_TIB NtTib;
        PVOID EnvironmentPointer;
        CLIENT_ID ClientId;//进程的的Pid 当前线程的的Tid
        PVOID ActiveRpcHandle;

        //程序运行时可以动态修改IMAGE_TLS_DIRECTORY.AddressOfCallBacks指向的函数指针数组的内容,实现动态更改系统会调用的TLS,但是此时修改IMAGE_TLS_DIRECTORY.AddressOfCallBacks的值已没有意义
        //tls_index exe无(为0),根据dll模块数目从1开始计数,用于索引fs:[2c]中相对应的指针,此指针指向由此模块的StartAddressOfRawData->EndAddressOfRawData生成的副本
        //每创建一个新的线程,挨个申请内存后拷贝有TLS数据的模块从StartAddressOfRawData到EndAddressOfRawData的数据,并将指针依次存入此线程的fs:[2c](其中每个线程的fs:[2c]指针数组值都不同但成员数相同==使用了TLS的静态链接的DLL+使用了TLS的EXE)(每个使用了静态TLS的模块的[tls_index]中记录了其静态TLS数据在fs:[2c]中的索引)
        PVOID ThreadLocalStoragePointer;//指向线程存储TLS数据的指针数组,从[fs:[2c]+[tls_index]*sizeof(void*)]这个地址开始的数据,是相应[tls_index]的模块从StartAddressOfRawData到EndAddressOfRawData的数据的副本
        PPEB ProcessEnvironmentBlock;

        ULONG LastErrorValue;//上一个错误号 GetLastError SetLastError
        ULONG CountOfOwnedCriticalSections;
        PVOID CsrClientThread;
        PVOID Win32ThreadInfo;
        ULONG User32Reserved[26];
        ULONG UserReserved[5];
        PVOID WOW32Reserved;//call fs:[0xC0]进入wow64环境 (为0则x86系统,不为0则x64系统)
        LCID CurrentLocale;
        ULONG FpSoftwareStatusRegister;
        PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
        PVOID SystemReserved1[30];
#else
        PVOID SystemReserved1[26];
#endif
        CHAR PlaceholderCompatibilityMode;
        CHAR PlaceholderReserved[11];
        ULONG ProxiedProcessId;
        ACTIVATION_CONTEXT_STACK ActivationStack;

        UCHAR WorkingOnBehalfTicket[8];
        NTSTATUS ExceptionCode;

        PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
        ULONG_PTR InstrumentationCallbackSp;
        ULONG_PTR InstrumentationCallbackPreviousPc;
        ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
        ULONG TxFsContext;
#endif
        BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
        UCHAR SpareBytes[23];
        ULONG TxFsContext;
#endif
        GDI_TEB_BATCH GdiTebBatch;
        CLIENT_ID RealClientId;
        HANDLE GdiCachedProcessHandle;
        ULONG GdiClientPID;
        ULONG GdiClientTID;
        PVOID GdiThreadLocalInfo;
        ULONG_PTR Win32ClientInfo[62];
        PVOID glDispatchTable[233];
        ULONG_PTR glReserved1[29];
        PVOID glReserved2;
        PVOID glSectionInfo;
        PVOID glSection;
        PVOID glTable;
        PVOID glCurrentRC;
        PVOID glContext;

        NTSTATUS LastStatusValue;
        UNICODE_STRING StaticUnicodeString;
        WCHAR StaticUnicodeBuffer[261];

        PVOID DeallocationStack;
        PVOID TlsSlots[64];//动态TLS
        LIST_ENTRY TlsLinks;

        PVOID Vdm;
        PVOID ReservedForNtRpc;
        PVOID DbgSsReserved[2];

        ULONG HardErrorMode;
#ifdef _WIN64
        PVOID Instrumentation[11];
#else
        PVOID Instrumentation[9];
#endif
        GUID ActivityId;

        PVOID SubProcessTag;
        PVOID PerflibData;
        PVOID EtwTraceData;
        PVOID WinSockData;
        ULONG GdiBatchCount;

        union
        {
            PROCESSOR_NUMBER CurrentIdealProcessor;
            ULONG IdealProcessorValue;
            struct
            {
                UCHAR ReservedPad0;
                UCHAR ReservedPad1;
                UCHAR ReservedPad2;
                UCHAR IdealProcessor;
            } s1;
        } u1;

        ULONG GuaranteedStackBytes;
        PVOID ReservedForPerf;
        PVOID ReservedForOle;
        ULONG WaitingOnLoaderLock;
        PVOID SavedPriorityState;
        ULONG_PTR ReservedForCodeCoverage;
        PVOID ThreadPoolData;
        PVOID* TlsExpansionSlots;//动态TLS
#ifdef _WIN64
        PVOID DeallocationBStore;
        PVOID BStoreLimit;
#endif
        ULONG MuiGeneration;
        ULONG IsImpersonating;
        PVOID NlsCache;
        PVOID pShimData;
        USHORT HeapVirtualAffinity;
        USHORT LowFragHeapDataSlot;
        HANDLE CurrentTransactionHandle;
        PTEB_ACTIVE_FRAME ActiveFrame;
        PVOID FlsData;

        PVOID PreferredLanguages;
        PVOID UserPrefLanguages;
        PVOID MergedPrefLanguages;
        ULONG MuiImpersonation;

        union
        {
            USHORT CrossTebFlags;
            USHORT SpareCrossTebBits : 16;
        } u2;
        union
        {
            USHORT SameTebFlags;
            struct
            {
                USHORT SafeThunkCall : 1;
                USHORT InDebugPrint : 1;
                USHORT HasFiberData : 1;
                USHORT SkipThreadAttach : 1;
                USHORT WerInShipAssertCode : 1;
                USHORT RanProcessInit : 1;
                USHORT ClonedThread : 1;
                USHORT SuppressDebugMsg : 1;
                USHORT DisableUserStackWalk : 1;
                USHORT RtlExceptionAttached : 1;
                USHORT InitialThread : 1;
                USHORT SessionAware : 1;
                USHORT LoadOwner : 1;
                USHORT LoaderWorker : 1;
                USHORT SkipLoaderInit : 1;
                USHORT SpareSameTebBits : 1;
            } s2;
        } u3;

        PVOID TxnScopeEnterCallback;
        PVOID TxnScopeExitCallback;
        PVOID TxnScopeContext;
        ULONG LockCount;
        LONG WowTebOffset;
        PVOID ResourceRetValue;
        PVOID ReservedForWdf;
        ULONGLONG ReservedForCrt;
        GUID EffectiveContainerId;
    } TEB, * PTEB;

#ifdef _WIN64
#define GetTEB    __readgsqword(0x30)
#define GetPEB    __readgsqword(0x60)
#else
#define GetTEB    __readfsdword(0x18)
#define GetPEB    __readfsdword(0x30)
#endif

#ifdef _WIN64//EAX、ECX、EDX、EBX、ESP、EBP、ESI、EDI
#define CIP Rip
#define CAX Rax
#define CCX Rcx
#define CDX Rdx
#define CBX Rbx
#define CSP Rsp
#define CBP Rbp
#define CSI Rsi
#define CDI Rdi
#else
#define CIP Eip
#define CAX Eax
#define CCX Ecx
#define CDX Edx
#define CBX Ebx
#define CSP Esp
#define CBP Ebp
#define CSI Esi
#define CDI Edi
#endif
}
