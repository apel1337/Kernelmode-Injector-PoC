#include <iostream>
#include <Windows.h>
#include <cstdio>
#include <string>
#include <locale>
#include <codecvt>
#include <type_traits>
#include <numbers>
#include <array>
#include <inttypes.h>

#include <functional>
#include <fileapi.h>
#include <TlHelp32.h>
#include <winuser.h>

#include <map>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include <d3d11.h>
#include <dwmapi.h>
#pragma comment(lib, "d3d11.lib")

#include <core/backend/skcrypt/skcrypter.h>
#include <core/backend/termcolor/termcolor.h>

#include <core/backend/resources/util/nt.h>
#include <core/backend/resources/raw_driver.h>
#include <core/backend/resources/kernel_ctx/kernel_ctx.h>
#include <core/backend/resources/drv_image/drv_image.h>
#include <core/backend/resources/physmeme/physmeme.h>

#include <core/driver/ia32/nt.hpp>
#include <core/driver/ia32/ia32.hpp>

#include <core/backend/libraries/direct/direct.h>

// target process
#ifdef _VALORANT
#define target_process L"Valorant-Win64-Shipping.exe"
#endif // _VALORANT

#ifdef _FORTNITE
#define target_process L"POLYGON-Win64-Shipping.exe"
#endif // _FORTNITE

//static_assert( false , "Please set the game configuration for you. You can switch the configuration above for Valorant OR Fortnite, the configurations are REQUIRED. DOUBLE CLICK AND DELETE ME!" );