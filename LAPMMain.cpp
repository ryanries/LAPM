/*
LAPMMain.cpp
Written by Joseph Ryan Ries, 2015

Questions? Concerns? Comments? Contact the author at ryanries09@gmail.com, ryan@myotherpcisacloud.com or through https://myotherpcisacloud.com.

COPYRIGHT AND DISCLAIMER NOTICE:

Copyright ©2015 Joseph Ryan Ries. All Rights Reserved.

IN NO EVENT SHALL JOSEPH RYAN RIES (HEREINAFTER REFERRED TO AS 'THE AUTHOR') BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND/OR ITS DOCUMENTATION, EVEN IF THE AUTHOR IS ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". THE AUTHOR HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT,
UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
*/

#define _CRT_RAND_S
#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <sddl.h>
#include <DsGetDC.h>
#include <LM.h>
#include <WbemIdl.h>
#include <Winldap.h>

#pragma comment(lib, "WbemUuid.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Netapi32.lib")

struct Version
{
	uint8_t Major;
	uint8_t Minor;
};

enum LOG_LEVEL
{
	LOG_INFO,
	LOG_WARN,
	LOG_ERROR
};

const Version GProductVersion = { 1, 0 };

wchar_t GPathToEventCreate[128] = { 0 };

const char GValidPwdChars[] = {       0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, // No space, to avoid confusion.
                                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                                0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E };

// NOTE(Ryan): This function returns true if the string ends with the specified Suffix/substring.
// Uses wide characters. Case sensitive.
int StringEndsWithW(_In_ const wchar_t *Str, _In_ const wchar_t *Suffix)
{
	if (Str == NULL || Suffix == NULL)
	{
		return 0;
	}

	size_t str_len = wcslen(Str);
	size_t suffix_len = wcslen(Suffix);

	if (suffix_len > str_len)
	{
		return 0;
	}

	return 0 == wcsncmp(Str + str_len - suffix_len, Suffix, suffix_len);
}

// NOTE(Ryan): This function returns true if the specified file name exists and is not a directory.
BOOL FileExists(_In_ LPCTSTR Path)
{
	DWORD Attributes = GetFileAttributes(Path);

	return (Attributes != INVALID_FILE_ATTRIBUTES && !(Attributes & FILE_ATTRIBUTE_DIRECTORY));
}

// NOTE(Ryan): This function wraps EventCreate.exe to write an event to the event log. 
// This is very cheesy, but it's also a huge pain in the ass to write event log events the normal way.
void EventCreateWrapper(_In_ wchar_t *PathToEventCreate, _In_ wchar_t *LogName, _In_ uint16_t Id, _In_ LOG_LEVEL Level, _In_ wchar_t *Source, _In_ const wchar_t *Message, _In_ ...)
{
	wchar_t FullEventCreateCommandLine[2048] = { 0 };
	wchar_t FormattedMessage[2048]           = { 0 };
	wchar_t IdToString[16]                   = { 0 };

	STARTUPINFO StartupInfo = { 0 };

	PROCESS_INFORMATION ProcessInfo = { 0 };

	va_list ArgPointer = NULL;

	if (wcslen(Message) > 1024)
	{
		return;
	}

	wcscat_s(FullEventCreateCommandLine, PathToEventCreate);

	switch (Level)
	{
		case LOG_INFO:
		{
			wcscat_s(FullEventCreateCommandLine, L" /T INFORMATION");
			break;
		}
		case LOG_WARN:
		{
			wcscat_s(FullEventCreateCommandLine, L" /T WARNING");
			break;
		}
		case LOG_ERROR:
		{
			wcscat_s(FullEventCreateCommandLine, L" /T ERROR");
			break;
		}
	}

	wcscat_s(FullEventCreateCommandLine, L" /ID ");

	_itow_s(Id, IdToString, sizeof(IdToString) / sizeof(wchar_t), 10);

	wcscat_s(FullEventCreateCommandLine, IdToString);

	wcscat_s(FullEventCreateCommandLine, L" /SO ");
	wcscat_s(FullEventCreateCommandLine, Source);

	wcscat_s(FullEventCreateCommandLine, L" /L ");
	wcscat_s(FullEventCreateCommandLine, LogName);

	wcscat_s(FullEventCreateCommandLine, L" /D \"");

	va_start(ArgPointer, Message);
	_vsnwprintf_s(FormattedMessage, sizeof(FormattedMessage), Message, ArgPointer);
	va_end(ArgPointer);

	wcscat_s(FullEventCreateCommandLine, FormattedMessage);

	wcscat_s(FullEventCreateCommandLine, L"\"");

	CreateProcess(NULL, FullEventCreateCommandLine, NULL, NULL, FALSE, NULL, NULL, NULL, &StartupInfo, &ProcessInfo);
	WaitForSingleObject(ProcessInfo.hProcess, 2000);
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
}

// NOTE(Ryan): Application entry point.
int wmain(_In_ int argc, _In_ wchar_t *argv[])
{
	wchar_t LocalAdminSID[64]         = { 0 };
	wchar_t LocalAdminName[64]        = { 0 };
	wchar_t SystemRoot[64]            = { 0 };
	wchar_t DomainController[256]     = { 0 };
	wchar_t DefaultNamingContext[256] = { 0 };
	wchar_t Username[64]              = { 0 };
	wchar_t LDAPComputerSearch[64]    = { 0 };
	wchar_t LDAPComputerDN[256]       = { 0 };
	wchar_t UnicodePassword[64]       = { 0 };

	wchar_t *LogName     = L"Application";
	wchar_t *EventSource = L"LAPM";
	
	LPWSTR CurrentUserSid[64] = { 0 };

	LDAP *LDAPConnection = NULL;

	LONG LDAPVersion = LDAP_VERSION3;
	LONG SSLOption = 0;

	LDAPMessage *LDAPResponse = NULL;

	PWCHAR *LDAPField = NULL;

	USER_INFO_1003 LocalUserInfo;	

	char NewPassword[17]   = { 0 };
	uint8_t PasswordLength = 16;	

	IWbemLocator         *WMILocator  = NULL;
	IWbemServices        *WMIServices = NULL;
	IEnumWbemClassObject *WMIResults  = NULL;
	IWbemClassObject     *WMIResult   = NULL;

	BSTR WMIResource = SysAllocString(L"ROOT\\CIMv2");
	BSTR WMILanguage = SysAllocString(L"WQL");
	BSTR WMIQuery    = SysAllocString(L"SELECT Roles FROM Win32_ComputerSystem");
	
	ULONG   WMIReturnCount     = 0;
	BOOL    IsDomainController = FALSE;
	
	HRESULT COMStatus  = S_OK;
	HRESULT WMIStatus  = S_OK;
	HRESULT LDAPStatus = S_OK;
	
	DWORD LocalStatus = S_OK;

	DWORD         RequiredTokenBufferSize = 0;
	HANDLE        TokenHandle = NULL;
	PTOKEN_USER   TokenInfo   = NULL;

	DOMAIN_CONTROLLER_INFO *DomainControllerInfo = NULL;	

	wprintf_s(L"\nLocal Admin Password Maintainer Version %d.%d\n", GProductVersion.Major, GProductVersion.Minor);
	wprintf_s(L"Written by Joseph Ryan Ries, 2015\n\n");

	if (argc != 2 || wcscmp(argv[1], L"BEGIN_MAGIC") != 0)
	{
		wprintf_s(L"This program only runs in an automated manner as a part of the LAPM solution.\n");
		return(EXIT_FAILURE);
	}

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &TokenHandle) == 0 || TokenHandle == NULL)
	{
		wprintf_s(L"OpenProcessToken failed with error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}

	GetTokenInformation(TokenHandle, TokenUser, NULL, 0, &RequiredTokenBufferSize);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || RequiredTokenBufferSize == 0)
	{
		wprintf_s(L"GetTokenInformation failed with error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}

	if ((TokenInfo = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RequiredTokenBufferSize)) == 0)
	{
		wprintf_s(L"HeapAlloc failed.\n");
		return(EXIT_FAILURE);
	}

	if (GetTokenInformation(TokenHandle, TokenUser, TokenInfo, RequiredTokenBufferSize, &RequiredTokenBufferSize) == 0)
	{
		wprintf_s(L"GetTokenInformation failed with error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}

	if (ConvertSidToStringSid(TokenInfo->User.Sid, CurrentUserSid) == 0)
	{
		wprintf_s(L"ConvertSidToStringSid failed with error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}	

	CloseHandle(TokenHandle);	

	if (_wcsicmp(L"S-1-5-18", *CurrentUserSid) != 0)
	{
		wprintf_s(L"This program only runs in an automated manner as a part of the LAPM solution.\n");
		return(EXIT_FAILURE);
	}
	
	// Since this program only runs as Local System, the environment variable "USERNAME" will
	// match the computer name in AD. We need this to query for the computer's sAMAccountName in AD.
	if (GetEnvironmentVariable(L"USERNAME", Username, sizeof(Username) / sizeof(wchar_t)) == 0)
	{
		wprintf_s(L"Get environment variable error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}

	if (GetEnvironmentVariable(L"SystemRoot", SystemRoot, sizeof(SystemRoot) / sizeof(wchar_t)) == 0)
	{
		wprintf_s(L"Get environment variable error 0x%x\n", GetLastError());
		return(EXIT_FAILURE);
	}

	wcscpy_s(GPathToEventCreate, SystemRoot);
	if (!StringEndsWithW(GPathToEventCreate, L"\\"))
	{
		wcscat_s(GPathToEventCreate, L"\\");
	}
	wcscat_s(GPathToEventCreate, L"System32\\Eventcreate.exe");

	if (!FileExists(GPathToEventCreate))
	{
		wprintf_s(L"Eventcreate.exe not found.\n");
		return(EXIT_FAILURE);
	}

	EventCreateWrapper(GPathToEventCreate, LogName, 100, LOG_INFO, EventSource, 
		L"Local Admin Password Maintainer Version %d.%d has started.", GProductVersion.Major, GProductVersion.Minor);

	for (uint8_t PasswordIndex = 0; PasswordIndex < PasswordLength; PasswordIndex++)
	{
		uint32_t Random = 0;
		rand_s(&Random);
		NewPassword[PasswordIndex] = GValidPwdChars[Random % sizeof(GValidPwdChars)];
	}	

	if ((COMStatus = CoInitializeEx(NULL, COINIT_MULTITHREADED)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 300, LOG_ERROR, EventSource, 
			L"CoInitializeEx failed with 0x%x. Local administrator password will not be changed.", COMStatus);
		return(COMStatus);
	}

	if ((COMStatus = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 301, LOG_ERROR, EventSource, 
			L"CoInitializeSecurity failed with 0x%x. Local administrator password will not be changed.", COMStatus);
		return(COMStatus);
	}

	if ((COMStatus = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&WMILocator)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 302, LOG_ERROR, EventSource, 
			L"CoCreateInstance failed with 0x%x. Local administrator password will not be changed.", COMStatus);
		return(COMStatus);
	}

	if ((COMStatus = WMILocator->ConnectServer(WMIResource, NULL, NULL, NULL, 0, NULL, NULL, &WMIServices)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 303, LOG_ERROR, EventSource, 
			L"IWbemLocator::ConnectServer failed with 0x%x. Local administrator password will not be changed.", COMStatus);		
		return(COMStatus);
	}

	if ((COMStatus = WMIServices->ExecQuery(WMILanguage, WMIQuery, WBEM_FLAG_BIDIRECTIONAL, NULL, &WMIResults)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 304, LOG_ERROR, EventSource, 
			L"IWbemServices::ExecQuery failed with 0x%x. Local administrator password will not be changed.", COMStatus);
		return(COMStatus);
	}

	if (WMIResults == NULL)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 305, LOG_ERROR, EventSource, 
			L"A critical WMI query returned an empty result. Local administrator password will not be changed.");
		return(EXIT_FAILURE);
	}

	while ((COMStatus = WMIResults->Next(WBEM_INFINITE, 1, &WMIResult, &WMIReturnCount)) == S_OK)
	{
		VARIANT Value;
		BSTR HUGEP *pBSTR;
		if ((COMStatus = WMIResult->Get(L"Roles", NULL, &Value, 0, 0)) != WBEM_S_NO_ERROR)
		{
			EventCreateWrapper(GPathToEventCreate, LogName, 306, LOG_ERROR, EventSource, 
				L"IWbemClassObject::Get failed with 0x%x. Local administrator password will not be changed.", COMStatus);
			return(COMStatus);
		}

		WMIStatus = SafeArrayAccessData(Value.parray, (void HUGEP* FAR*)&pBSTR);
		if (WMIStatus != S_OK)
		{			
			EventCreateWrapper(GPathToEventCreate, LogName, 307, LOG_ERROR, EventSource, 
				L"SafeArrayAccessData failed with 0x%x. Local administrator password will not be changed.", WMIStatus);
			return(WMIStatus);
		}

		for (uint8_t RoleIndex = 0; RoleIndex < Value.parray[0].rgsabound->cElements; RoleIndex++)
		{
			if (_wcsicmp(pBSTR[RoleIndex], L"Primary_Domain_Controller") == 0 || _wcsicmp(pBSTR[RoleIndex], L"Backup_Domain_Controller") == 0)
			{
				IsDomainController = TRUE;
			}
		}
		SafeArrayUnaccessData(Value.parray);
		WMIResult->Release();
		VariantClear(&Value);
	}

	if (IsDomainController == TRUE)
	{		
		EventCreateWrapper(GPathToEventCreate, LogName, 101, LOG_INFO, EventSource, 
			L"This computer is a domain controller. No changes will be performed.");
		return(EXIT_SUCCESS);
	}

	SysFreeString(WMIQuery);
	WMIQuery = SysAllocString(L"SELECT * FROM Win32_UserAccount WHERE LocalAccount = True");
	if ((COMStatus = WMIServices->ExecQuery(WMILanguage, WMIQuery, WBEM_FLAG_BIDIRECTIONAL, NULL, &WMIResults)) != S_OK)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 308, LOG_ERROR, EventSource, 
			L"IWbemServices::ExecQuery failed with 0x%x. Local administrator password will not be changed.", COMStatus);
		return(COMStatus);
	}

	while ((COMStatus = WMIResults->Next(WBEM_INFINITE, 1, &WMIResult, &WMIReturnCount)) == S_OK)
	{
		VARIANT Value;
		wchar_t Sid[64] = { 0 };
		if ((COMStatus = WMIResult->Get(L"SID", NULL, &Value, 0, 0)) != WBEM_S_NO_ERROR)
		{
			EventCreateWrapper(GPathToEventCreate, LogName, 309, LOG_ERROR, EventSource, 
				L"IWbemClassObject::Get failed with 0x%x. Local administrator password will not be changed.", COMStatus);
			return(COMStatus);
		}

		wcscpy_s(Sid, Value.bstrVal);

		if (StringEndsWithW(Sid, L"-500"))
		{
			VARIANT Name;
			wcscpy_s(LocalAdminSID, Value.bstrVal);
			if ((COMStatus = WMIResult->Get(L"Name", NULL, &Name, 0, 0)) != WBEM_S_NO_ERROR)
			{
				EventCreateWrapper(GPathToEventCreate, LogName, 310, LOG_ERROR, EventSource, 
					L"IWbemClassObject::Get failed with 0x%x. Local administrator password will not be changed.", COMStatus);
				return(COMStatus);
			}
			wcscpy_s(LocalAdminName, Name.bstrVal);
			VariantClear(&Name);
		}
		WMIResult->Release();
		VariantClear(&Value);		
	}

	if (wcslen(LocalAdminName) == 0 || wcslen(LocalAdminSID) == 0)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 311, LOG_ERROR, EventSource, 
			L"Could not locate the local administrator account and/or its SID! Local administrator password will not be changed.", COMStatus);
		return(EXIT_FAILURE);
	}

	if (DsGetDcName(NULL, NULL, NULL, NULL, DS_WRITABLE_REQUIRED | DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME | DS_FORCE_REDISCOVERY, &DomainControllerInfo) != ERROR_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 312, LOG_ERROR, EventSource, 
			L"DsGetDcName failed. Ensure you are connected to your domain's network. Local administrator password will not be changed.");
		return(EXIT_FAILURE);
	}

	_snwprintf_s(DomainController, sizeof(DomainController), DomainControllerInfo->DomainControllerName);	

	if (DomainController[0] == '\\')
	{
		wcscpy_s(DomainController, DomainController + 2);
	}

	LDAPConnection = ldap_sslinit(DomainController, LDAP_SSL_PORT, 1);
	if (LDAPConnection == NULL)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 313, LOG_ERROR, EventSource, 
			L"ldap_sslinit failed with error 0x%x. Domain controllers must be reachable and using trusted certificates for LDAP over SSL. Local administrator password will not be changed. DC: %s", LdapGetLastError(), DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	ldap_set_option(LDAPConnection, LDAP_OPT_PROTOCOL_VERSION, (void *)&LDAPVersion);
	
	LDAPStatus = ldap_connect(LDAPConnection, NULL);
	if (LDAPStatus != LDAP_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 314, LOG_ERROR, EventSource, 
			L"ldap_connect failed with error 0x%x. Domain controllers must be reachable and using trusted certificates for LDAP over SSL. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}	

	LDAPStatus = ldap_get_option(LDAPConnection, LDAP_OPT_SSL, (void *)&SSLOption);
	if (LDAPStatus != LDAP_SUCCESS || (void *)SSLOption != LDAP_OPT_ON)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 315, LOG_ERROR, EventSource, 
			L"LDAP connection to %s succeeded, but the server did not appear to be using SSL. Local administrator password will not be changed.", DomainController);		
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	LDAPStatus = ldap_bind_s(LDAPConnection, NULL, NULL, LDAP_AUTH_NEGOTIATE);
	if (LDAPStatus != LDAP_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 316, LOG_ERROR, EventSource, 
			L"ldap_bind_s failed with error 0x%x. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	LDAPStatus = ldap_search_s(LDAPConnection, NULL, LDAP_SCOPE_BASE, NULL, NULL, FALSE, &LDAPResponse);
	if (LDAPStatus != LDAP_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 317, LOG_ERROR, EventSource, 
			L"ldap_search_s failed with error 0x%x. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	LDAPField = ldap_get_values(LDAPConnection, LDAPResponse, L"defaultNamingContext");
	if (ldap_count_values(LDAPField) == 0)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 318, LOG_ERROR, EventSource, 
			L"ldap_get_values returned 0 results. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	_snwprintf_s(DefaultNamingContext, sizeof(DefaultNamingContext), *LDAPField);

	wcscpy_s(LDAPComputerSearch, L"(&(objectClass=computer)(sAMAccountName=");
	wcscat_s(LDAPComputerSearch, Username); // NOTE(Ryan): e.g. MEMBER01$
	wcscat_s(LDAPComputerSearch, L"))");

	LDAPStatus = ldap_search_s(LDAPConnection, DefaultNamingContext, LDAP_SCOPE_SUBTREE, LDAPComputerSearch, NULL, FALSE, &LDAPResponse);
	if (LDAPStatus != LDAP_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 319, LOG_ERROR, EventSource, 
			L"ldap_search_s failed with error 0x%x. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	LDAPField = ldap_get_values(LDAPConnection, LDAPResponse, L"distinguishedName");
	if (ldap_count_values(LDAPField) == 0)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 320, LOG_ERROR, EventSource, 
			L"ldap_get_values returned 0 results. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	_snwprintf_s(LDAPComputerDN, sizeof(LDAPComputerDN), *LDAPField);	

	LDAPMod *LDAPMods[2];
	LDAPMod NewPasswordLDAPMod;
	BERVAL pwdBerVal;
	BERVAL *pwd_attr[2];

	LDAPMods[0] = &NewPasswordLDAPMod;
	LDAPMods[1] = NULL;

	NewPasswordLDAPMod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
	NewPasswordLDAPMod.mod_type = L"LAPMLocalAdminPassword";
	NewPasswordLDAPMod.mod_vals.modv_bvals = pwd_attr;

	pwd_attr[0] = &pwdBerVal;
	pwd_attr[1] = NULL;

	pwdBerVal.bv_len = strlen(NewPassword);
	pwdBerVal.bv_val = NewPassword;

	LDAPStatus = ldap_modify_s(LDAPConnection, LDAPComputerDN, LDAPMods);
	if (LDAPStatus != LDAP_SUCCESS)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 321, LOG_ERROR, EventSource, 
			L"ldap_modify_s failed with error 0x%x. Local administrator password will not be changed. DC: %s", LDAPStatus, DomainController);
		ldap_unbind(LDAPConnection);
		return(EXIT_FAILURE);
	}

	ldap_unbind(LDAPConnection);

	EventCreateWrapper(GPathToEventCreate, LogName, 102, LOG_INFO, EventSource, 
		L"New local administrator password successfully uploaded to domain controller.");

	mbstowcs_s(0, UnicodePassword, NewPassword, strlen(NewPassword) + 1);

	LocalUserInfo.usri1003_password = UnicodePassword;

	LocalStatus = NetUserSetInfo(NULL, LocalAdminName, 1003, (LPBYTE)&LocalUserInfo, NULL);
	if (LocalStatus != NERR_Success)
	{
		EventCreateWrapper(GPathToEventCreate, LogName, 322, LOG_ERROR, EventSource, 
			L"Failed to set the local administrator password on the local computer! Error: 0x%x", LocalStatus);
		return(EXIT_FAILURE);
	}
	
	EventCreateWrapper(GPathToEventCreate, LogName, 103, LOG_INFO, EventSource, 
		L"New local administrator password changed successfully.");
	
	return(EXIT_SUCCESS);
}