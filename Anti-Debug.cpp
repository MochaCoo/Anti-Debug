#include "Anti-Debug.h"
#include "NEW_TEB_PEB_SEH.h"
#include <stdio.h>
#include <tchar.h>

#define MyReadMemory(handle,addr,type,name) \
type name;\
ReadProcessMemory(handle, (LPVOID)(addr), &(name), sizeof(name), NULL)

#define MyReadMemory2v(handle,addr,name) ReadProcessMemory(handle, (LPVOID)(addr), &(name), sizeof(name), NULL)

#define MyWriteMemory(handle,addr,name) WriteProcessMemory(handle, (LPVOID)(addr), &(name), sizeof(name), NULL)

//向下取整
#define ALIGN_DOWN(length, type) \
	((ULONG_PTR)(length) & ~(sizeof(type) - 1))
//向上取整
#define ALIGN_UP(length, type) \
	(ALIGN_DOWN(((ULONG_PTR)(length) + sizeof(type) - 1), type))

EXTERN_C void MyInt3();

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

bool CheckDebug_DebugPort() {
	ULONG_PTR dwDebugPort = 0;
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, sizeof(dwDebugPort), 0);
	//printf("dwDebugPort:%d\n", dwDebugPort);
	return dwDebugPort == -1;
}

bool CheckDebug_DebugHandle() {
	ULONG_PTR dwDebugHandle = 0;
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &dwDebugHandle, sizeof(dwDebugHandle), 0);
	return dwDebugHandle != 0;
}

bool CheckDebug_DebugFlags() {
	bool bDebugFlags = 0;
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &bDebugFlags, 1, 0);
	//printf("%d\n", bDebugFlags);
	return bDebugFlags == 0;
}

bool CheckDebug_QueryObject() {
	typedef enum _OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation, // Result is OBJECT_BASIC_INFORMATION structure 
		ObjectNameInformation, // Result is OBJECT_NAME_INFORMATION structure 
		ObjectTypeInformation, // Result is OBJECT_TYPE_INFORMATION structure 
		ObjectAllTypesInformation, // Result is OBJECT_ALL_INFORMATION structure 
		ObjectDataInformation // Result is OBJECT_DATA_INFORMATION structure 

	} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;
	typedef NTSTATUS
	(WINAPI* pNtQueryObject)(
		_In_opt_ HANDLE Handle,
		_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
		_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
		_In_ ULONG ObjectInformationLength,
		_Out_opt_ PULONG ReturnLength
		);
	typedef struct _OBJECT_TYPE_INFORMATION
	{
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfObjects;//TotalNumberOfObjects和TotalNumberOfHandles不同文档顺序不一样
		ULONG TotalNumberOfHandles;
		//此结构体还有其他字段...
		//整个结构体的最末尾会存储TypeName的字符串,然后就是下一个结构体+其TypeName的字符串,以此往复
	}OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;
	typedef struct _OBJECT_ALL_INFORMATION
	{
		ULONG NumberOfObjectsTypes;
		OBJECT_TYPE_INFORMATION ObjectTypeInfo[1];
	}OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;
	pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryObject");
	//1.获取欲查询信息大小
	ULONG uSize = 0;
	NtQueryObject(NULL, ObjectAllTypesInformation, &uSize, sizeof(uSize), &uSize);
	//2.获取对象大信息
	POBJECT_ALL_INFORMATION pObjectAllInfo = (POBJECT_ALL_INFORMATION)VirtualAlloc(NULL, uSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pObjectAllInfo == NULL) {
		return CheckDebugFail;//申请内存失败
	}
	NtQueryObject(NULL, ObjectAllTypesInformation, pObjectAllInfo, uSize, &uSize);
	//3.循环遍历并处理对象信息
	POBJECT_TYPE_INFORMATION pObjectTypeInfo = pObjectAllInfo->ObjectTypeInfo;
	for (int i = 0; i < pObjectAllInfo->NumberOfObjectsTypes; i++)
	{
		//3.1查看此对象的类型是否为DebugObject
		if (!wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer))
		{
			bool ret;
			ret = pObjectTypeInfo->TotalNumberOfObjects > 0 ? true : false;
			VirtualFree(pObjectAllInfo, NULL, MEM_RELEASE);
			return ret;
		}
		//3.2指向下一个对象信息
		pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)((PBYTE)pObjectTypeInfo->TypeName.Buffer + ALIGN_UP(pObjectTypeInfo->TypeName.MaximumLength, ULONG_PTR));
	}
	VirtualFree(pObjectAllInfo, NULL, MEM_RELEASE);
	return false;
}

LONG WINAPI CloseHandle_filter(
	_In_ struct _EXCEPTION_POINTERS* ExceptionInfo
) {
	//printf("debug");
	SetLastError(1);
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool CheckDebug_CloseHandle() {
	typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);
	pNtClose NtClose = (pNtClose)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtClose");
	AddVectoredExceptionHandler(0, CloseHandle_filter);
	SetLastError(0);
	NtClose((HANDLE)0x1234);
	if (GetLastError() == 1)
		return true;
	return false;
}

LONG WINAPI DuplicateHandle_filter(
	_In_ struct _EXCEPTION_POINTERS* ExceptionInfo
) {
	//printf("debug");
	SetLastError(1);
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool CheckDebug_DuplicateHandle()
{
	AddVectoredExceptionHandler(0, DuplicateHandle_filter);

	HANDLE hTarget, hNewTarget;
	// 将当前进程的伪句柄柄转换为真实句柄并保存在hTarget中 (其他类型的句柄也可以, 如CreateMutexW创建的句柄)
	DuplicateHandle((HANDLE)-1, (HANDLE)-1, (HANDLE)-1, &hTarget, 0, 0, DUPLICATE_SAME_ACCESS);
	// 为句柄hTarget设置HANDLE_FLAG_PROTECT_FROM_CLOSE属性, 执行之后, 句柄hTarget将禁止关闭
	SetHandleInformation(hTarget, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
	// 复制源句柄hTarget给hNewTarget, 然后尝试关闭句柄hTarget
	// 因为调用了SetHandleInformation设置源句柄禁止关闭, 当程序被调试器调试时, 去尝试关闭句柄(如DuplicateHandle, CloseHandle)会触发异常
	SetLastError(0);
	DuplicateHandle((HANDLE)-1, (HANDLE)hTarget, (HANDLE)-1, &hNewTarget, 0, 0, DUPLICATE_CLOSE_SOURCE);
	if (GetLastError() == 1)
		return true;
	return false;
}

int TryToAttachProcess(DWORD pid)
{
	if (DebugActiveProcess(pid)) {//分别触发对应异常
		DebugActiveProcessStop(pid);//没有调试器
		//DebugBreak();//使用WINDOWS API同时适用于x86x64但是导入表中会出现DebugBreak
#ifdef _WIN64
		MyInt3();
#else
		__asm int 3//触发BREAKPOINT异常
#endif
		
		return 0;
	}
	else {
		DWORD zero = 0;//有调试器
		pid = pid / zero;//触发除0异常
		return pid;
	}
}

bool IsAddrInPEModule(HANDLE hProcess, ULONG_PTR ImageBase, PVOID addr)
{
	//PVOID BaseAddr = (PVOID)GetModuleHandle(0);
	MyReadMemory(hProcess, ImageBase + offsetof(IMAGE_DOS_HEADER, e_lfanew), LONG, e_lfanew);
	ULONG_PTR nth = ImageBase + e_lfanew;
	MyReadMemory(hProcess, nth + offsetof(IMAGE_NT_HEADERS, OptionalHeader.SizeOfImage), DWORD, SizeOfImage);
	if (ImageBase <= (ULONG_PTR)addr && (ULONG_PTR)addr < ImageBase + SizeOfImage)
		return true;
	else
		return false;
}
/*
流程:
创建自身的一个被调试子进程->进程启动时修改入口点等待触发异常(此时进程IAT，重定位等都没处理,不能直接执行TryToAttachProcess)
入口点异常触发->构造好调用环境,修改R/Eip指向TryToAttachProcess
根据TryToAttachProcess触发的异常类型判断DebugActiveProcess是否附加成功->构造好调用环境,修改R/Eip指向ExitProcess让子进程自己退出
*/
bool CheckDebug_DebugActiveProcess()
{
	TCHAR file[MAX_PATH];
	GetModuleFileName(0, file, MAX_PATH);

	STARTUPINFOW si{ 0 };
	PROCESS_INFORMATION pi{ 0 };
	CreateProcess(file, NULL, NULL, NULL, false, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);

	DEBUG_EVENT de{ 0 };
	ULONG_PTR ImageBase = 0;
	CONTEXT EntryPoint{};
	EntryPoint.ContextFlags = CONTEXT_FULL;
	CONTEXT c{};
	c.ContextFlags = CONTEXT_FULL;

	DWORD op;
	while (TRUE)
	{
		DWORD dwContinueStatus = DBG_CONTINUE;
		WaitForDebugEvent(&de, INFINITE);
		bool isdebug;
		switch (de.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT://和CREATE_SUSPENDED的时机相同
			CloseHandle(de.u.CreateProcessInfo.hFile);//不使用时需要关闭
			GetThreadContext(pi.hThread, &EntryPoint);
#ifdef _WIN64//x64和x86下暂停方式创建的进程获取到的环境指向入口点的寄存器不同,设置入口点为NOACCESS,进程初始化完开始执行入口点就会触发异常
			VirtualProtectEx(pi.hProcess, (LPVOID)EntryPoint.Rcx, 1, PAGE_NOACCESS, &op);
#else
			VirtualProtectEx(pi.hProcess, (LPVOID)EntryPoint.Eax, 1, PAGE_NOACCESS, &op);
#endif
			//SuspendThread(pi.hThread);
			//DebugActiveProcessStop(pi.dwProcessId);
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION: {
#ifdef _WIN64
				if (de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)EntryPoint.Rcx)
#else
				if (de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)EntryPoint.Eax)
#endif
				{
					c.ContextFlags = CONTEXT_FULL;
					GetThreadContext(pi.hThread, &c);
#ifdef _WIN64//x64和x86下暂停方式创建的进程获取到的环境指向PEB的寄存器不同
					c.Rsp -= sizeof(DWORD64) * (4 + 1);
					c.Rcx = GetCurrentProcessId();
					MyReadMemory2v(pi.hProcess, EntryPoint.Rdx + 16, ImageBase);
					c.Rip = ImageBase + (DWORD64)TryToAttachProcess - (DWORD64)GetModuleHandle(0);
					DWORD op2;
					VirtualProtectEx(pi.hProcess, (LPVOID)EntryPoint.Rcx, 1, op, &op2);//避免覆盖到了TryToAttachProcess函数,造成再次异常,下同
#else
					c.Esp -= sizeof(DWORD);
					DWORD Pid = GetCurrentProcessId();
					MyWriteMemory(pi.hProcess, c.Esp, Pid);
					c.Esp -= sizeof(DWORD);//模拟call压入的返回地址

					MyReadMemory2v(pi.hProcess, EntryPoint.Ebx + 8, ImageBase);
					c.Eip = ImageBase + (DWORD)TryToAttachProcess - (DWORD)GetModuleHandle(0);
					DWORD op2;
					VirtualProtectEx(pi.hProcess, (LPVOID)EntryPoint.Eax, 1, op, &op2);
#endif
					SetThreadContext(pi.hThread, &c);
				}
				else {
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
				break;
			}
			case EXCEPTION_BREAKPOINT: {//没有调试器
				if (ImageBase == NULL)//这个是判断系统断点的情况
					goto systembreakpoint;
				GetThreadContext(pi.hThread, &c);
				/*
				//使用DebugBreak()A而不是asm文件时的代码
				MyReadMemory(pi.hProcess, c.CSP, ULONG_PTR, retaddr);//x64的DebugBreakAPI没有prolog,可以进行调用栈回溯
				if (IsAddrInPEModule(pi.hProcess, ImageBase, (LPVOID)retaddr))
				*/
				if (IsAddrInPEModule(pi.hProcess, ImageBase, (LPVOID)de.u.Exception.ExceptionRecord.ExceptionAddress))
				{
					isdebug = false;
				ExitChildProcess:
#ifdef _WIN64
					c.Rsp -= sizeof(DWORD64) * (4 + 1);
					c.Rcx = 0;//ExitProcess(0)
#else
					DWORD retzero = 0;
					c.Esp -= sizeof(DWORD);
					MyWriteMemory(pi.hProcess, c.CSP, retzero);
					c.Esp -= sizeof(DWORD);//模拟call压入的返回地址
#endif
					c.CIP = (ULONG_PTR)ExitProcess;
					SetThreadContext(pi.hThread, &c);

					ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
					DebugActiveProcessStop(pi.dwProcessId);

					//Sleep(10000);
					//STILL_ACTIVE
					//DWORD ExitCode;
					//GetExitCodeProcess(pi.hProcess, &ExitCode);
					//printf("ExitCode:%x\n", ExitCode);

					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					return isdebug;
				}
				else {
				systembreakpoint:
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
				break;
			}
			case EXCEPTION_INT_DIVIDE_BY_ZERO://有调试器
				if (IsAddrInPEModule(pi.hProcess, ImageBase, de.u.Exception.ExceptionRecord.ExceptionAddress)) {
					isdebug = true;
					GetThreadContext(pi.hThread, &c);
					goto ExitChildProcess;
				}
				else {
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
				break;
			}
		case LOAD_DLL_DEBUG_EVENT://加载DLL
			CloseHandle(de.u.LoadDll.hFile);//不使用时需要关闭
			break;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
	return false;
}
#ifndef _WIN64
bool CheckDebug_WOW64_1E_NtQueryInformationProcess()
{
	wow64init();
	DWORD64 h = GetModuleHandle64(L"ntdll.dll");
	DWORD64 addr = GetProcAddress64(h, "NtQueryInformationProcess");
	DWORD64 r = 0;
	X64Call(addr, 5, (DWORD64)-1, (DWORD64)0x1E, (DWORD64)&r, (DWORD64)sizeof(DWORD64), (DWORD64)0);
	if (r != 0)
		return true;
	return false;
}

bool CheckDebug_WOW64_7_NtQueryInformationProcess()
{
	wow64init();
	DWORD64 h = GetModuleHandle64(L"ntdll.dll");
	DWORD64 addr = GetProcAddress64(h, "NtQueryInformationProcess");
	DWORD64 r = 0;
	X64Call(addr, 5, (DWORD64)-1, (DWORD64)7, (DWORD64)&r, (DWORD64)sizeof(DWORD64), (DWORD64)0);
	if (r == -1)
		return true;
	return false;
}

bool AntiDebug_WOW64_ZwSetInformationThread()
{
	wow64init();
	DWORD64 h = GetModuleHandle64(L"ntdll.dll");
	DWORD64 addr = GetProcAddress64(h, "ZwSetInformationThread");
	DWORD64 r = 0;
	return X64Call(addr, 4, (DWORD64)-2, (DWORD64)17, (DWORD64)0, (DWORD64)0);
}

bool AntiDebug_WOW64_NtCreateThreadEx(PVOID func,DWORD64 parm, DWORD64 CreateFlag)
{
	wow64init();
	DWORD64 h = GetModuleHandle64(L"ntdll.dll");
	DWORD64 addr = GetProcAddress64(h, "NtCreateThreadEx");
	DWORD64 handle = 0;
	return X64Call(addr, 11, (DWORD64)&handle, (DWORD64)0x1FFFFF, (DWORD64)0, (DWORD64)-1, (DWORD64)func, (DWORD64)parm, (DWORD64)CreateFlag, (DWORD64)0, (DWORD64)0, (DWORD64)0, (DWORD64)0);
}
#endif