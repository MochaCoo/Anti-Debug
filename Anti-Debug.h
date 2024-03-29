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

#define CheckDebugFail true//�޷��жϵ���������ʱ��⺯������ֵ
bool CheckDebug_DebugPort();
bool CheckDebug_DebugHandle();
bool CheckDebug_DebugFlags();//�˷���win7����ʧЧ?
bool CheckDebug_QueryObject();//���ڵ��Զ���ͻ᷵����,��һ���Ǳ����̱�����
bool CheckDebug_CloseHandle();//�������Ϊ�����������쳣����̽�ⲻ��������;��鿴x64dbgѡ��->�쳣->ѡ���쳣������->�쳣������
bool CheckDebug_DuplicateHandle();//����CloseHandle

//int TryToAttachProcess(DWORD pid);
//bool IsAddrInPEModule(HANDLE hProcess, ULONG_PTR ImageBase, PVOID addr);
bool CheckDebug_DebugActiveProcess();
#ifndef _WIN64
bool CheckDebug_WOW64_1E_NtQueryInformationProcess();
bool CheckDebug_WOW64_7_NtQueryInformationProcess();
bool AntiDebug_WOW64_ZwSetInformationThread();//ʹ��ǰ�̶߳Ե���������
bool AntiDebug_WOW64_NtCreateThreadEx(PVOID func, DWORD64 parm, DWORD64 CreateFlag);//0 ������ͨ�̵߳����ƹ��Ự����/ 1 ����ͣ�ķ�ʽ�����߳� / 2 ��������ʼ��user32���߳�,���ᴥ��dllmain,����ʼ��win32k(������x86����x64NtCreateThreadEx,win10�д˱�־���߳̿��Ե���LoadLibrary����ģ��,win7����,��������ִ����������user32.dll���API) / 4 THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER�����Ե��������ص��߳�
#endif