#include <iostream>
#include"Anti-Debug.h"
using namespace std;
#define X64END "\xE8\x00\x00\x00\x00\xC7\x44\x24\x04\x23\x00\x00\x00\x83\x04\x24\x0D\xCB"
#define DEBUGTEST(x) cout<<#x<<": "<<x

void __stdcall HideThread() {
	MessageBoxA(0, "Hide", "Hide", 0);
	ExitThread(0);//��Ϊƽջ��ԭ��,��Ҫ��ExitThread�˳��߳�
}

int main() {
	cout << "���淽��" << endl;
	DEBUGTEST(CheckDebug_DebugPort()) << endl;
	DEBUGTEST(CheckDebug_DebugHandle()) << endl;
	//DEBUGTEST(CheckDebug_DebugFlags()) << endl;
	DEBUGTEST(CheckDebug_QueryObject())<<"//���ڵ��Զ���ͻ᷵����, ��һ���Ǳ����̱�����"<<endl;
	DEBUGTEST(CheckDebug_CloseHandle()) << "//�������Ϊ�����������쳣����̽�ⲻ��������;��鿴x64dbgѡ��->�쳣->ѡ���쳣������->�쳣������" << endl;
	DEBUGTEST(CheckDebug_DuplicateHandle()) << "//����CloseHandle" << endl;

	cout << "���·��������ƹ� ScyllaHide���κ�������ԭ��ķ������Բ��" << endl;
	/*ʹ����process-hollowing�ļ���ԭ��ķ����Լ���*/
	DEBUGTEST(CheckDebug_DebugActiveProcess()) << endl;

	/*wow64������*/
#ifndef _WIN64//wow64����ר�õ��Լ�ⷽ��
	DEBUGTEST(CheckDebug_WOW64_1E_NtQueryInformationProcess()) << endl;
	DEBUGTEST(CheckDebug_WOW64_7_NtQueryInformationProcess()) << endl;
	DEBUGTEST(AntiDebug_WOW64_ZwSetInformationThread()) << endl;//���̶߳Ե���������,�����ڴ��߳���ִ��crcУ���,���������޷�������������̵߳��κε�����Ϣ,��ͬ

	PVOID p = VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(p, X64END, sizeof(X64END) - 1);//NtCreateThreadEx�������߳���Ҫͨ��X64END��CPUģʽ��x64�����л���x86����״̬
	*(char*)((char*)p + sizeof(X64END) - 1) = 0xB8;
	*(DWORD*)((char*)p + sizeof(X64END)) = (DWORD)HideThread;
	*(WORD*)((char*)p + sizeof(X64END) + 4) = (WORD)0xD0FF;
	DEBUGTEST(AntiDebug_WOW64_NtCreateThreadEx(p,0x123,4)) << endl;//�������̶߳Ե���������
	MessageBoxA(0, "���ܱ��¶ϵ�MsgBox", "AntiDebug", 0);
#endif
	system("pause");
}