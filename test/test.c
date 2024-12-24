#include <Windows.h>
#include <tlhelp32.h>

DECLSPEC_IMPORT VOID    BEACON$BeaconPrintf( INT Type, PCHAR Format, ... );
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID );
DECLSPEC_IMPORT BOOL    KERNEL32$Process32First( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
DECLSPEC_IMPORT BOOL    KERNEL32$Process32Next( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
DECLSPEC_IMPORT BOOL    KERNEL32$CloseHandle( HANDLE hObject );

int go() {
  HANDLE          hProcessSnap;
  HANDLE          hProcess;
  PROCESSENTRY32  pe32;

  hProcessSnap = KERNEL32$CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    BEACON$BeaconPrintf( 0, "[!] CreateToolhelp32Snapshot Failed\n" );
    return( FALSE );
  }

  pe32.dwSize = sizeof( PROCESSENTRY32 );

  if( !KERNEL32$Process32First( hProcessSnap, &pe32 ) )
  {
    BEACON$BeaconPrintf( 0, "Process32First Failed\n" );
    KERNEL32$CloseHandle( hProcessSnap ); 
    return( FALSE );
  }

  do
  {
    BEACON$BeaconPrintf( 0, "[*]  PROCESS NAME:  %s\n\t- PID: %d\n\t- PPID: %d\n\n", pe32.szExeFile, pe32.th32ProcessID, pe32.th32ParentProcessID );
  } while( KERNEL32$Process32Next( hProcessSnap, &pe32 ) );

  KERNEL32$CloseHandle( hProcessSnap );

  return (0);
}
