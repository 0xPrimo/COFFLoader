#include <Windows.h>
#include <stdio.h>

/* COFFLoader types */
typedef struct {
	UINT16  Machine;
	UINT16  NumberOfSections;
	UINT32  TimeDateStamp;
	UINT32  PointerToSymbolTable;
	UINT32  NumberOfSymbols;
	UINT16  SizeOfOptionalHeader;
	UINT16  Characteristics;
} COFF_FILE_HEADER, * PCOFF_FILE_HEADER;

#pragma pack(push,1)

typedef struct {
	UINT8       Name[ 8 ];
	UINT32      VirtualSize;
	UINT32      VirtualAddress;
	UINT32      SizeOfRawData;
	UINT32      PointerToRawData;
	UINT32      PointerToRelocations;
	UINT32      PointerToLineNumbers;
	UINT16      NumberOfRelocations;
	UINT16      NumberOfLinenumbers;
	UINT32      Characteristics;
} COFF_SECTION, * PCOFF_SECTION;

typedef struct {
	UINT32  VirtualAddress;
	UINT32  SymbolTableIndex;
	UINT16  Type;
} COFF_RELOC, * PCOFF_RELOC;

typedef struct {
	union
	{
		CHAR        ShortName[ 8 ];
		UINT32      Value[ 2 ];
	} First;

	UINT32  Value;
	INT16   SectionNumber;
	UINT16  Type;
	UINT8   StorageClass;
	UINT8   NumberOfAuxSymbols;
} COFF_SYMBOL, * PCOFF_SYMBOL;

typedef struct {
	PCOFF_SECTION   Header;
	PBYTE           Ptr;
	SIZE_T          Size;
} SECTION_MAP, * PSECTION_MAP;

typedef struct {
	PCOFF_FILE_HEADER   Header;
	PSECTION_MAP        Section;
	PCOFF_SYMBOL        Symbol;
	PBYTE               SymbolString;
	PBYTE               GOT;            // Global Offset Table
} COFF_CONTEXT, * PCOFF_CONTEXT;

/********************/

LPVOID ProcessSymbol( PCHAR Name )
{
	PCHAR	LibraryName = NULL;
	PCHAR	FunctionName = NULL;
	HMODULE hLibrary = NULL;
	CHAR	Temp[ 256 ] = { 0 };

	memcpy( Temp, Name, strlen( Name ) );

	/*
	* TODO: Beacon APIs.
	*/

	/*
	* split the symbol string.
	*	- Example: __imp_LIB'\0'FunctionName
	*/
	LibraryName = Temp + 0x06;
	FunctionName = strchr( Temp, '$' );
	if ( FunctionName == NULL ) {
		puts( "[!] Character '$' not found in symbol string" );
		return ( NULL );
	}

	*FunctionName = 0;
	FunctionName++;

	/* Load library */
	hLibrary = LoadLibraryA( LibraryName );
	if ( !hLibrary )
	{
		printf( "[!] LoadLibraryA Failed: %d\n", GetLastError( ) );
		return NULL;
	}

	/* Get procedure call address */
	return ( PBYTE ) GetProcAddress( hLibrary, FunctionName );
}

VOID Initialize( PCOFF_CONTEXT Context, PBYTE ObjectFile )
{
	PCOFF_SECTION	Section = NULL;

	Context->Header = ( PCOFF_FILE_HEADER ) ObjectFile;
	Context->Symbol = ObjectFile + Context->Header->PointerToSymbolTable;
	Context->SymbolString = ( PBYTE ) Context->Symbol + ( Context->Header->NumberOfSymbols * sizeof( COFF_SYMBOL ) );

	if ( !( Context->GOT = VirtualAlloc( NULL, 1337, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
	{
		printf( "[!] Initialize::VirtualAlloc: %d\n", GetLastError( ) );
		return ( FALSE );
	}

	if ( !( Context->Section = LocalAlloc( LPTR, Context->Header->NumberOfSections * sizeof( SECTION_MAP ) ) ) )
	{
		printf( "[!] Initialize::LocalAlloc: %d\n", GetLastError( ) );
		return ( FALSE );
	}

	for ( DWORD SecIndex = 0; SecIndex < Context->Header->NumberOfSections; SecIndex++ )
	{
		Section = ObjectFile + sizeof( COFF_FILE_HEADER ) + ( sizeof( COFF_SECTION ) * SecIndex );

		if ( Section->SizeOfRawData )
		{
			if ( !( Context->Section[ SecIndex ].Ptr = VirtualAlloc( NULL, Section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
			{
				printf( "[!] Initialize::VirtualAlloc: %d\n", GetLastError( ) );
				return ( FALSE );
			}

			Context->Section[ SecIndex ].Size = Section->SizeOfRawData;
			memcpy( Context->Section[ SecIndex ].Ptr, ObjectFile + Section->PointerToRawData, Section->SizeOfRawData );
		}

		Context->Section[ SecIndex ].Header = Section;
	}
}

LPBYTE ReadFileFromDisk( LPSTR FilePath, PSIZE_T MemorySize )
{
	HANDLE hFile = NULL;
	LPVOID FileBuffer = NULL;
	SIZE_T FileSize = 0;

	hFile = CreateFileA( FilePath, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
	if ( hFile == INVALID_HANDLE_VALUE ) {
		printf( "[-] ReadFileFromDisk::CreateFileA(): %d\n", GetLastError( ) );
		goto CLEANUP;
	}

	FileSize = GetFileSize( hFile, 0 );
	if ( FileSize == INVALID_FILE_SIZE ) {
		printf( "[-] ReadFileFromDisk::GetFileSize(): %d\n", GetLastError( ) );
		goto CLEANUP;
	}

	FileBuffer = LocalAlloc( LPTR, FileSize );
	if ( !FileBuffer ) {
		printf( "[-] ReadFileFromDisk::LocalAlloc(): %d\n", GetLastError( ) );
		goto CLEANUP;
	}

	if ( !ReadFile( hFile, FileBuffer, FileSize, NULL, NULL ) ) {
		printf( "[-] ReadFileFromDisk::ReadFile(): %d\n", GetLastError( ) );
		goto CLEANUP;
	}

	if ( hFile )
		CloseHandle( hFile );

	return ( FileBuffer );

CLEANUP:
	if ( hFile )
		CloseHandle( hFile );
	if ( FileBuffer )
		LocalFree( FileBuffer );

	return ( NULL );
}

INT main( int argc, char* argv[ ] )
{
	PBYTE			ObjectFile = NULL;
	COFF_CONTEXT	Context = { 0 };

	ObjectFile = ReadFileFromDisk( argv[ 1 ], NULL );
	if ( !ObjectFile )
		return ( 1 );

	puts( "[*] Initializing" );
	Initialize( &Context, ObjectFile );

	puts( "[*] Fixing Sections" );
	for ( DWORD SecIndex = 0; SecIndex < Context.Header->NumberOfSections; SecIndex++ )
	{
		if ( Context.Section[ SecIndex ].Header->NumberOfRelocations == 0 )
			continue;

		/* relocations */
		PCOFF_RELOC		Relocation = ObjectFile + Context.Section[ SecIndex ].Header->PointerToRelocations;
		LPVOID			SymbolAddr = NULL;
		PCHAR			SymbolString = NULL;
		DWORD			SymbolStringCounter = 0;
		UINT64			Offset64 = 0;
		UINT64			Offset32 = 0;

		for ( DWORD RelocIndex = 0; RelocIndex < Context.Section[ SecIndex ].Header->NumberOfRelocations; RelocIndex++ )
		{
			if ( Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].First.ShortName[ 0 ] != 0 )
			{
				if ( Relocation[ RelocIndex ].Type == IMAGE_REL_AMD64_ADDR64 )
				{
					memcpy( &Offset64, Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, sizeof( UINT64 ) );
					Offset64 = Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset64;
					memcpy( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, &Offset64, sizeof( UINT64 ) );
				}
				else if ( Relocation[ RelocIndex ].Type == IMAGE_REL_AMD64_ADDR32NB )
				{
					memcpy( &Offset32, Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, sizeof( UINT32 ) );

					if ( ( ( Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset32 ) - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 ) ) > 0xffffffff )
					{
						puts( "[!] Relocation 4 gigs away" );
						return ( 1 );
					}

					Offset32 = ( Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset32 ) - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 );

					memcpy( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, &Offset32, sizeof( UINT32 ) );
				}
				else if ( IMAGE_REL_AMD64_REL32 <= Relocation[ RelocIndex ].Type && Relocation[ RelocIndex ].Type <= IMAGE_REL_AMD64_REL32_5 )
				{
					memcpy( &Offset32, Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, sizeof( UINT32 ) );

					if ( ( ( Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr ) - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 ) ) > 0xffffffff )
					{
						puts( "[!] Relocation 4 gigs away" );
						return ( 1 );
					}

					Offset32 += Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Relocation[ RelocIndex ].Type - 4 ) - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 );

					memcpy( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, &Offset32, sizeof( UINT32 ) );
				}

			}
			else {
				SymbolString = Context.SymbolString + Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].First.Value[ 1 ];
				SymbolAddr = ProcessSymbol( SymbolString );

				if ( Relocation[ RelocIndex ].Type == IMAGE_REL_AMD64_REL32 && SymbolAddr != NULL )
				{
					if ( ( ( Context.GOT + ( SymbolStringCounter * 8 ) ) - Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 ) > 0xFFFFFFFF )
						return ( 1 );

					memcpy( Context.GOT + ( SymbolStringCounter * 8 ), &SymbolAddr, sizeof( UINT64 ) );
					Offset32 = ( Context.GOT + ( SymbolStringCounter * 8 ) ) - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 );
					memcpy( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, &Offset32, sizeof( UINT32 ) );

					SymbolStringCounter++;
				}
				else if ( Relocation[ RelocIndex ].Type == IMAGE_REL_AMD64_REL32 )
				{
					memcpy( &Offset32, Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, sizeof( UINT32 ) );

					if ( ( Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 ) ) > 0xFFFFFFFF )
					{
						puts( "[!] Relocation 4 gigs away" );
						return ( 1 );
					}

					Offset32 += Context.Section[ Context.Symbol[ Relocation[ RelocIndex ].SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress + 4 );
					memcpy( Context.Section[ SecIndex ].Ptr + Relocation[ RelocIndex ].VirtualAddress, &Offset32, sizeof( UINT32 ) );
				}
			}


		}
	}

	puts( "[*] Running Object File\n" );
	typedef VOID( *ENTRYPOINT ) ( );

	ENTRYPOINT  EntryPoint = NULL;
	DWORD       OldProtection = 0;
	BOOL        Success = FALSE;

	for ( DWORD SymCounter = 0; SymCounter < Context.Header->NumberOfSymbols; SymCounter++ )
	{
		if ( !strcmp( Context.Symbol[ SymCounter ].First.ShortName, argv[ 2 ] ) )
		{
			Success = TRUE;

			// set the .text section to RX
			VirtualProtect( Context.Section[ 0 ].Ptr, Context.Section[ 0 ].Size, PAGE_EXECUTE_READ, &OldProtection );
			EntryPoint = ( ENTRYPOINT ) ( Context.Section[ Context.Symbol[ SymCounter ].SectionNumber - 1 ].Ptr + Context.Symbol[ SymCounter ].Value );
			EntryPoint( );
			break;
		}
	}

	puts( "\n[*] Cleaning" );
	for ( DWORD SecIndex = 0; SecIndex < Context.Header->NumberOfSections; SecIndex++ )
	{
		if ( Context.Section[ SecIndex ].Ptr )
			VirtualFree( Context.Section[ SecIndex ].Ptr, Context.Section[ SecIndex ].Size, MEM_RELEASE );
	}

	if ( Context.GOT )
		VirtualFree( Context.GOT, 1337, MEM_RELEASE );

	if ( Context.Section )
		LocalFree( Context.Section );

	puts( "[+] Done." );
	return ( 0 );
}