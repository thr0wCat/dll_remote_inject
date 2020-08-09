
// injectDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "inject.h"
#include "injectDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <afxpriv.h>
#pragma comment(lib,"shlwapi.lib")


#ifdef _DEBUG
#define new DEBUG_NEW
#endif
//进程名取PID
DWORD GetProcessIDFromName(const TCHAR* pRocName) {

	HANDLE hSnapshot = NULL;
	BOOL bStatus = FALSE;
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pi = { 0 };
	pi.dwSize = sizeof(pi);
	hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == NULL)
	{
		return NULL;
	}
	bStatus = ::Process32First(hSnapshot, &pi);
	while (bStatus)
	{
		if (memcmp(pRocName,pi.szExeFile,::_tcslen(pRocName)) == 0)
		{
			dwProcessId = pi.th32ProcessID;
			break;


		}
		bStatus = ::Process32Next(hSnapshot,&pi);
	}
	if (hSnapshot != NULL)
	{
		::CloseHandle(hSnapshot);

	}
	return dwProcessId;


}
BOOL RemoteInjectDll(const TCHAR* pProcName, const TCHAR* pDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	DWORD dwSize = 0, dwProcessId = 0;
	BOOL bRet = FALSE;
	TCHAR* pRemoteBuf = NULL;
	LPTHREAD_START_ROUTINE lpThreadFun = NULL;



	// 参数无效  
	if (pProcName == NULL || ::_tcslen(pProcName) == 0
		|| pDllPath == NULL || ::_tcslen(pDllPath) == 0)
	{
		return FALSE;
	}

	// 指定 Dll 文件不存在  
	if (_taccess(pDllPath, 0) == -1)
	{
		return false;
	}

	do
	{
		//获取进程ID
		dwProcessId = GetProcessIDFromName(pProcName);
		if (dwProcessId == 0)
		{
			break;
		}

		// 获取目标进程句柄  
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			break;
		}

		// 在目标进程中分配内存空间  
		dwSize = (DWORD)::_tcslen(pDllPath) + 1;
		pRemoteBuf = (TCHAR*)::VirtualAllocEx(hProcess, NULL, dwSize * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
		if (pRemoteBuf == NULL)
		{
			break;
		}

		// 在目标进程的内存空间中写入所需参数(模块名)  
		if (FALSE == ::WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)pDllPath, dwSize * sizeof(TCHAR), NULL))
		{
			break;
		}

		// 获取 LoadLibrary 地址  
#ifdef _UNICODE  
		lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
#else  
		lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryA");
#endif  
		if (lpThreadFun == NULL)
		{
			break;
		}

		// 创建远程线程调用 LoadLibrary  
		hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpThreadFun, pRemoteBuf, 0, NULL);
		if (hThread == NULL)
		{
			break;
		}
		// 等待远程线程结束  
		::WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;

	} while (0);


	if (hThread != NULL)
	{
		::CloseHandle(hThread);
	}
	if (pRemoteBuf != NULL)
	{
		::VirtualFreeEx(hProcess, pRemoteBuf, dwSize, MEM_DECOMMIT);
	}
	if (hProcess != NULL)
	{
		::CloseHandle(hProcess);
	}
	return bRet;
}
BOOL UnRemoteInjectDll(const TCHAR* pProcName, const TCHAR* pDllPath)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE, hProcess = NULL, hThread = NULL;
	TCHAR *pModuleName = PathFindFileName(pDllPath);
	BOOL bRet = FALSE, bFound = FALSE;
	DWORD dwProcessId = 0;
	MODULEENTRY32 me32 = { 0 };;
	me32.dwSize = sizeof(me32);

	// 参数无效
	if (pProcName == NULL || ::_tcslen(pProcName) == 0
		|| pDllPath == NULL || ::_tcslen(pDllPath) == 0)
	{
		return FALSE;
	}

	do
	{
		//获取进程ID
		dwProcessId = GetProcessIDFromName(pProcName);
		if (dwProcessId == 0)
		{
			break;
		}

		// 获取模块快照  
		hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			break;
		}

		if (::Module32First(hModuleSnap, &me32) == FALSE)
		{
			break;
		}

		do
		{
			bFound = (::_tcsicmp(me32.szModule, pModuleName) == 0
				|| ::_tcsicmp(me32.szExePath, pDllPath) == 0);
			// 找到指定模块 
			if (bFound)
			{
				break;
			}
		} while (::Module32Next(hModuleSnap, &me32) == TRUE);

		if (false == bFound)
		{
			break;
		}

		// 获取目标进程句柄  
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			break;
		}

		// 获取 FreeLibrary 地址  
		LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(
			::GetModuleHandle(_T("Kernel32")), "FreeLibrary");
		if (lpThreadFun == NULL)
		{
			break;
		}

		// 创建远程线程调用 FreeLibrary  
		hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun,
			me32.modBaseAddr, 0, NULL);
		if (hThread == NULL)
		{
			break;
		}
		// 等待远程线程结束  
		::WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	} while (0);

	if (hThread != NULL)
	{
		::CloseHandle(hThread);
	}
	if (hProcess != NULL)
	{
		::CloseHandle(hProcess);
	}
	if (hModuleSnap != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hModuleSnap);
	}
	return bRet; 
}


CinjectDlg::CinjectDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_INJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CinjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comproc);
	DDX_Control(pDX, IDC_EDIT1, m_dllpath);
}

BEGIN_MESSAGE_MAP(CinjectDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CinjectDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CinjectDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CinjectDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CinjectDlg::OnBnClickedButton4)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


// CinjectDlg 消息处理程序

BOOL CinjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	OnBnClickedButton2();
	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CinjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CinjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CinjectDlg::OnBnClickedButton1()//注入按钮
{
	int comIndex = m_comproc.GetCurSel();
	CString pName;
	m_comproc.GetLBText(comIndex, pName);
	TRACE("pName:");
	TRACE(pName);
	CString dllpath;
	m_dllpath.GetWindowText(dllpath);
	TCHAR* tpname = new TCHAR[100];
	TCHAR* dllp = new TCHAR[100];
	tpname = pName.GetBuffer(pName.GetLength());
	dllp = dllpath.GetBuffer(dllpath.GetLength());

	if (pName == "" || dllpath == "")
	{
		AfxMessageBox(_T("EXE或Dll路径为空! 拖入Dll可获取路径!"));
		return;
	}
	if (RemoteInjectDll(tpname, dllp) == TRUE)
	{
		AfxMessageBox(_T("注入成功!"));
		return;
	}
	AfxMessageBox(_T("注入失败!"));

	//m_comproc.getcur
	// TODO: 在此添加控件通知处理程序代码
}


void CinjectDlg::OnBnClickedButton2()//刷新按钮
{
	m_comproc.ResetContent();
	HANDLE hSnapshot = NULL;
	BOOL bStatus = FALSE;
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pi = { 0 };
	pi.dwSize = sizeof(pi);
	hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == NULL)
	{
		AfxMessageBox(_T("创建失败"));
	}
	bStatus = ::Process32First(hSnapshot, &pi);
	while (bStatus)
	{
		
		m_comproc.AddString(pi.szExeFile);
		
		bStatus = ::Process32Next(hSnapshot, &pi);
	}
	if (hSnapshot != NULL)
	{
		::CloseHandle(hSnapshot);

	}
	m_comproc.SetCurSel(0);

	// TODO: 在此添加控件通知处理程序代码
}


void CinjectDlg::OnBnClickedButton3()//卸载
{
	int comIndex = m_comproc.GetCurSel();
	CString pName;
	m_comproc.GetLBText(comIndex, pName);
	TRACE("pName:");
	TRACE(pName);
	CString dllpath;
	m_dllpath.GetWindowText(dllpath);
	TCHAR* tpname = new TCHAR[100];
	TCHAR* dllp = new TCHAR[100];
	tpname = pName.GetBuffer(pName.GetLength());
	dllp = dllpath.GetBuffer(dllpath.GetLength());

	if (pName == "" || dllpath == "")
	{
		AfxMessageBox(_T("EXE或Dll路径为空! 拖入Dll可获取路径!"));
		return;
	}
	if (UnRemoteInjectDll(tpname, dllp) == TRUE)
	{
		AfxMessageBox(_T("卸载成功!"));
		return;
	}
	AfxMessageBox(_T("卸载失败!"));

	//m_comproc.getcur
	// TODO: 在此添加控件通知处理程序代码
}


void CinjectDlg::OnBnClickedButton4()
{
	exit(0);
	// TODO: 在此添加控件通知处理程序代码
}


void CinjectDlg::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szfilepath[MAX_PATH];
	DragQueryFile(hDropInfo, 0, szfilepath ,sizeof(szfilepath));
	CString cstr;
	cstr.Format(L"%s", szfilepath);
	m_dllpath.SetWindowTextW(cstr);
	DragFinish(hDropInfo);
	CDialogEx::OnDropFiles(hDropInfo);
}

