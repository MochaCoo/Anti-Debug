#pragma once
//#include "rewolf-wow64ext-master/src/wow64ext.h"
#include <Windows.h>
#include <winternl.h>
#ifndef _WIN64
#pragma comment(lib,"./Release/wow64ext.lib")
#endif
extern "C" {
	void wow64init();
	DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
	DWORD64 __cdecl GetModuleHandle64(wchar_t* lpModuleName);
	DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, char* funcName);
}

#define CheckDebugFail true//无法判断调试器存在时检测函数返回值
bool CheckDebug_DebugPort();
bool CheckDebug_DebugHandle();
bool CheckDebug_DebugFlags();//此方法win7下已失效?
bool CheckDebug_QueryObject();//存在调试对象就会返回真,不一定是本进程被调试
bool CheckDebug_CloseHandle();//如果设置为调试器处理异常者则探测不到调试器;请查看x64dbg选项->异常->选中异常处理器->异常处理者
bool CheckDebug_DuplicateHandle();//类似CloseHandle

//int TryToAttachProcess(DWORD pid);
//bool IsAddrInPEModule(HANDLE hProcess, ULONG_PTR ImageBase, PVOID addr);
bool CheckDebug_DebugActiveProcess();
#ifndef _WIN64
bool CheckDebug_WOW64_1E_NtQueryInformationProcess();
bool CheckDebug_WOW64_7_NtQueryInformationProcess();
bool AntiDebug_WOW64_ZwSetInformationThread();//使当前线程对调试器隐藏
bool AntiDebug_WOW64_NtCreateThreadEx(PVOID func, DWORD64 parm, DWORD64 CreateFlag);//0 创建普通线程但是绕过会话隔离/ 1 以暂停的方式创建线程 / 2 启动不初始化user32的线程,不会触发dllmain,不初始化win32k(无论是x86还是x64NtCreateThreadEx,win10中此标志的线程可以调用LoadLibrary加载模块,win7不行,但都可以执行其他除了user32.dll里的API) / 4 THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER启动对调试器隐藏的线程
#endif