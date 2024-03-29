#include <iostream>
#include"Anti-Debug.h"
using namespace std;
#define X64END "\xE8\x00\x00\x00\x00\xC7\x44\x24\x04\x23\x00\x00\x00\x83\x04\x24\x0D\xCB"
#define DEBUGTEST(x) cout<<#x<<": "<<x

void __stdcall HideThread() {
	MessageBoxA(0, "Hide", "Hide", 0);
	ExitThread(0);//因为平栈的原因,需要用ExitThread退出线程
}

int main() {
	cout << "常规方法" << endl;
	DEBUGTEST(CheckDebug_DebugPort()) << endl;
	DEBUGTEST(CheckDebug_DebugHandle()) << endl;
	//DEBUGTEST(CheckDebug_DebugFlags()) << endl;
	DEBUGTEST(CheckDebug_QueryObject())<<"//存在调试对象就会返回真, 不一定是本进程被调试"<<endl;
	DEBUGTEST(CheckDebug_CloseHandle()) << "//如果设置为调试器处理异常者则探测不到调试器;请查看x64dbg选项->异常->选中异常处理器->异常处理者" << endl;
	DEBUGTEST(CheckDebug_DuplicateHandle()) << "//类似CloseHandle" << endl;

	cout << "以下方法均能绕过 ScyllaHide或任何有类似原理的反反调试插件" << endl;
	/*使用了process-hollowing的技术原理的反调试技术*/
	DEBUGTEST(CheckDebug_DebugActiveProcess()) << endl;

	/*wow64反调试*/
#ifndef _WIN64//wow64进程专用调试检测方法
	DEBUGTEST(CheckDebug_WOW64_1E_NtQueryInformationProcess()) << endl;
	DEBUGTEST(CheckDebug_WOW64_7_NtQueryInformationProcess()) << endl;
	DEBUGTEST(AntiDebug_WOW64_ZwSetInformationThread()) << endl;//主线程对调试器隐藏,可以在此线程中执行crc校验等,而调试器无法接受来自这个线程的任何调试消息,下同

	PVOID p = VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(p, X64END, sizeof(X64END) - 1);//NtCreateThreadEx创建的线程需要通过X64END将CPU模式从x64解码切换到x86解码状态
	*(char*)((char*)p + sizeof(X64END) - 1) = 0xB8;
	*(DWORD*)((char*)p + sizeof(X64END)) = (DWORD)HideThread;
	*(WORD*)((char*)p + sizeof(X64END) + 4) = (WORD)0xD0FF;
	DEBUGTEST(AntiDebug_WOW64_NtCreateThreadEx(p,0x123,4)) << endl;//创建的线程对调试器隐藏
	MessageBoxA(0, "不能被下断的MsgBox", "AntiDebug", 0);
#endif
	system("pause");
}