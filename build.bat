@echo off
REM 编译脚本 - 使用 MinGW-w64 编译32位和64位版本
REM 需要同时安装32位和64位的MinGW-w64工具链

echo ========================================
echo 编译 Window Display Affinity Tool
echo 32位和64位版本
echo ========================================

REM 设置编译器路径 (根据实际安装路径修改)
set GCC64=gcc
set GCC32=i686-w64-mingw32-gcc

REM 检查是否有32位编译器
where %GCC32% >nul 2>&1
if %errorlevel% neq 0 (
    echo 警告: 找不到32位编译器 %GCC32%
    echo 将只编译64位版本
    set BUILD32=0
) else (
    set BUILD32=1
)

echo.
echo [1/4] 编译64位主程序...
%GCC64% -o WindowAffinityTool64.exe main.c -lgdi32 -lcomctl32 -ladvapi32 -luser32 -mwindows -municode -O2
if %errorlevel% neq 0 (
    echo 64位主程序编译失败!
    goto :error
)
echo 成功: WindowAffinityTool64.exe

echo.
echo [2/4] 编译64位DLL...
%GCC64% -shared -o inject_dll64.dll inject_dll.c -luser32 -municode -O2
if %errorlevel% neq 0 (
    echo 64位DLL编译失败!
    goto :error
)
echo 成功: inject_dll64.dll

if "%BUILD32%"=="0" goto :skip32

echo.
echo [3/4] 编译32位主程序...
%GCC32% -o WindowAffinityTool32.exe main.c -lgdi32 -lcomctl32 -ladvapi32 -luser32 -mwindows -municode -O2
if %errorlevel% neq 0 (
    echo 32位主程序编译失败!
    goto :error
)
echo 成功: WindowAffinityTool32.exe

echo.
echo [4/4] 编译32位DLL...
%GCC32% -shared -o inject_dll32.dll inject_dll.c -luser32 -municode -O2
if %errorlevel% neq 0 (
    echo 32位DLL编译失败!
    goto :error
)
echo 成功: inject_dll32.dll

:skip32
echo.
echo ========================================
echo 编译完成!
echo.
echo 生成文件:
echo   64位版本:
echo     - WindowAffinityTool64.exe
echo     - inject_dll64.dll
if "%BUILD32%"=="1" (
echo   32位版本:
echo     - WindowAffinityTool32.exe
echo     - inject_dll32.dll
)
echo.
echo 使用说明:
echo   1. 以管理员权限运行任意版本的主程序
echo   2. 程序会自动检测目标进程架构
echo   3. 如需注入不同架构的进程，需要两个版本都存在
echo   4. Shellcode注入方式不需要DLL文件
echo ========================================
goto :eof

:error
echo.
echo 编译出错!
exit /b 1
