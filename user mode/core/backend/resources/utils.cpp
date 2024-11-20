#include <core/backend/resources/stdafx.h>

namespace riot
{
	namespace utils
	{
        std::wstring to_lower( std::wstring str )
        {
            std::transform( str.begin( ) , str.end( ) , str.begin( ) , ::towlower );
            return str;
        }

        std::wstring ansi_to_wstring( const std::string& input , DWORD locale /*= CP_ACP*/ )
        {
            if ( input.empty( ) ) return std::wstring( );

            int size_needed = MultiByteToWideChar( locale , 0 , input.c_str( ) , ( int ) input.length( ) , nullptr , 0 );
            std::wstring result( size_needed , 0 );
            MultiByteToWideChar( locale , 0 , input.c_str( ) , ( int ) input.length( ) , &result[ 0 ] , size_needed );
            return result;
        }

        std::string wstring_to_ansi( const std::wstring& input , DWORD locale /*= CP_ACP*/ )
        {
            if ( input.empty( ) ) return std::string( );

            int size_needed = WideCharToMultiByte( locale , 0 , input.c_str( ) , ( int ) input.length( ) , nullptr , 0 , nullptr , nullptr );
            std::string result( size_needed , 0 );
            WideCharToMultiByte( locale , 0 , input.c_str( ) , ( int ) input.length( ) , &result[ 0 ] , size_needed , nullptr , nullptr );
            return result;
        }

        std::wstring strip_path( const std::wstring& path )
        {
            size_t pos = path.find_last_of( L"\\/" );
            if ( pos != std::wstring::npos )
                return path.substr( pos + 1 );
            return path;
        }

        bool file_exists( const std::wstring& path )
        {
            DWORD attrib = GetFileAttributesW( path.c_str( ) );
            return ( attrib != INVALID_FILE_ATTRIBUTES && !( attrib & FILE_ATTRIBUTE_DIRECTORY ) );
        }

        std::wstring get_exe_directory( )
        {
            wchar_t path[ MAX_PATH ];
            GetModuleFileNameW( nullptr , path , MAX_PATH );
            std::wstring exePath( path );
            return exePath.substr( 0 , exePath.find_last_of( L"\\" ) );
        }

        DWORD get_os_version( )
        {
            OSVERSIONINFOEXW osInfo;
            ZeroMemory( &osInfo , sizeof( OSVERSIONINFOEXW ) );
            osInfo.dwOSVersionInfoSize = sizeof( OSVERSIONINFOEXW );

            if ( !GetVersionExW( ( LPOSVERSIONINFOW ) &osInfo ) )
            {
                printf( "Failed to retrieve OS version.\n" );
                return 0;
            }

            if ( osInfo.dwMajorVersion == 10 )
            {
                return g_Win10;
            }
            else if ( osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 1 )
            {
                return g_Win7;
            }

            return 0;
        }

        std::wstring get_process_directory( std::uint32_t process_pid )
        {
            HANDLE snapshot;
            MODULEENTRY32W mod = { sizeof( MODULEENTRY32W ), 0 };
            std::wstring path = L"";

            if ( ( snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , process_pid ) ) &&
                Module32FirstW( snapshot , &mod ) != FALSE
                )
            {
                path = mod.szExePath;
                path = path.substr( 0 , path.rfind( L"\\" ) );
            }

            return path;
        }

        NTSTATUS ProbeSxSRedirect( std::wstring& path , HANDLE actx /*= INVALID_HANDLE_VALUE*/ )
        {
            UNICODE_STRING OriginalName = { 0 };
            UNICODE_STRING DllName1 = { 0 };
            UNICODE_STRING DllName2 = { 0 };
            PUNICODE_STRING pPath = nullptr;
            ULONG_PTR cookie = 0;
            wchar_t wBuf[ 255 ];

            RtlInitUnicodeString( &OriginalName , path.c_str( ) );

            DllName1.Buffer = wBuf;
            DllName1.Length = NULL;
            DllName1.MaximumLength = sizeof( wBuf );

            // Use activation context
            if ( actx != INVALID_HANDLE_VALUE )
                ActivateActCtx( actx , &cookie );

            // SxS resolve
            NTSTATUS status =
                RtlDosApplyFileIsolationRedirection_Ustr( TRUE , &OriginalName , ( PUNICODE_STRING ) NULL ,
                    &DllName1 , &DllName2 , &pPath ,
                    nullptr , nullptr , nullptr
                );

            if ( cookie != 0 && actx != INVALID_HANDLE_VALUE )
                DeactivateActCtx( 0 , cookie );

            if ( status == STATUS_SUCCESS )
            {
                path = pPath->Buffer;
            }
            else
            {
                if ( DllName2.Buffer )
                    RtlFreeUnicodeString( &DllName2 );
            }

            return status;
        }

        NTSTATUS resolve_path(
            std::wstring& path ,
            const std::wstring& baseName ,
            const std::wstring& searchDir ,
            std::uint32_t process_id ,
            HANDLE actx /*= INVALID_HANDLE_VALUE*/ ,
        )
        {
            NTSTATUS status = 0;
            wchar_t tmpPath[ 4096 ] = { 0 };
            std::wstring completePath;

            path = to_lower( std::move( path ) );

            // Leave only file name
            std::wstring filename = strip_path( path );

            // 'ext-ms-' are resolved the same way 'api-ms-' are
            //if ( !( injector::OSVersion >= g_Win10 ) && filename.find( L"ext-ms-" ) == 0 )
            //    filename.erase( 0 , 4 );

            //
            // ApiSchema redirection
            //
            //auto iter = std::find_if( m_api_schema.begin( ) , m_api_schema.end( ) , [ &filename ] ( const auto& val ) {
            //    return filename.find( val.first.c_str( ) ) != filename.npos; } );

            //if ( iter != m_api_schema.end( ) )
            //{
            //    // Select appropriate api host
            //    if ( !iter->second.empty( ) )
            //        path = iter->second.front( ) != baseName ? iter->second.front( ) : iter->second.back( );
            //    else
            //        path = baseName;

            //    status = ProbeSxSRedirect( path , actx );
            //    if ( NT_SUCCESS( status ) || status == STATUS_SXS_IDENTITIES_DIFFERENT )
            //    {
            //        return status;
            //    }

            //    wchar_t sys_path[ 255 ] = { 0 };
            //    GetSystemDirectoryW( sys_path , 255 );

            //    path = std::wstring( sys_path ) + L"\\" + path;

            //    return STATUS_SUCCESS;
            //}

            // SxS redirection
            status = ProbeSxSRedirect( path , actx );
            if ( NT_SUCCESS( status ) || status == STATUS_SXS_IDENTITIES_DIFFERENT )
                return status;

            // Already a full-qualified name
            if ( file_exists( path ) )
                return STATUS_SUCCESS;

            //
            // Perform search accordingly to Windows Image loader search order 
            // 1. KnownDlls
            //
            HKEY hKey;
            LRESULT res = 0;
            res = RegOpenKeyW( HKEY_LOCAL_MACHINE , L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs" , &hKey );

            if ( res == 0 )
            {
                for ( int i = 0; i < 0x1000 && res == ERROR_SUCCESS; i++ )
                {
                    wchar_t value_name[ 255 ] = { 0 };
                    wchar_t value_data[ 255 ] = { 0 };

                    DWORD dwSize = 255;
                    DWORD dwType = 0;

                    res = RegEnumValueW( hKey , i , value_name , &dwSize , NULL , &dwType , reinterpret_cast< LPBYTE >( value_data ) , &dwSize );

                    if ( _wcsicmp( value_data , filename.c_str( ) ) == 0 )
                    {
                        wchar_t sys_path[ 255 ] = { 0 };
                        dwSize = 255;

                        // In Win10 DllDirectory value got screwed, so less reliable method is used
                         GetSystemDirectoryW( sys_path , dwSize );

                        if ( res == ERROR_SUCCESS )
                        {
                            path = std::wstring( sys_path ) + L"\\" + value_data;
                            return STATUS_SUCCESS;
                        }
                    }
                }
            }


            //
            // 2. Parent directory of the image being resolved
            //
            if ( !searchDir.empty( ) )
            {
                completePath = searchDir + L"\\" + filename;
                if ( file_exists( completePath ) )
                {
                    path = completePath;
                    return STATUS_SUCCESS;
                }
            }

            //
            // 3. The directory from which the application was started.
            //
            completePath = get_process_directory( process_id ) + L"\\" + filename;

            if ( file_exists( completePath ) )
            {
                path = completePath;
                return STATUS_SUCCESS;
            }

            //
            // 4. The system directory
            //
            GetSystemDirectoryW( tmpPath , ARRAYSIZE( tmpPath ) );

            completePath = std::wstring( tmpPath ) + L"\\" + filename;

            if ( file_exists( completePath ) )
            {
                path = completePath;
                return STATUS_SUCCESS;
            }

            //
            // 5. The Windows directory
            //
            GetWindowsDirectoryW( tmpPath , ARRAYSIZE( tmpPath ) );

            completePath = std::wstring( tmpPath ) + L"\\" + filename;

            if ( file_exists( completePath ) )
            {
                path = completePath;
                return STATUS_SUCCESS;
            }

            //
            // 6. The current directory
            //
            GetCurrentDirectoryW( ARRAYSIZE( tmpPath ) , tmpPath );

            completePath = std::wstring( tmpPath ) + L"\\" + filename;

            if ( file_exists( completePath ) )
            {
                path = completePath;
                return STATUS_SUCCESS;
            }

            //
            // 7. Directories listed in PATH environment variable
            //
            GetEnvironmentVariableW( L"PATH" , tmpPath , ARRAYSIZE( tmpPath ) );
            wchar_t* pContext;

            for ( wchar_t* pDir = wcstok_s( tmpPath , L";" , &pContext ); pDir; pDir = wcstok_s( pContext , L";" , &pContext ) )
            {
                completePath = std::wstring( pDir ) + L"\\" + filename;

                if ( file_exists( completePath ) )
                {
                    path = completePath;
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_NOT_FOUND;
        }
	}
}