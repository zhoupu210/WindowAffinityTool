# Window Affinity Modify Tool

一个 Windows 工具，用于设置任意窗口的 `SetWindowDisplayAffinity` 属性，使其在屏幕录制/截图软件中不可见。

## 演示

https://github.com/user-attachments/assets/19616f9f-3598-4a3f-a2d2-7a5942ec46b5

## 功能

- **三种显示模式：**
  - **Visible（可见）** - 正常窗口，可被截图/录屏捕获
  - **Black（黑屏）** - 在截图/录屏中显示为黑色
  - **Hidden（隐藏）** - 在截图/录屏中完全不可见

- **多种注入方式：**
  - Remote Thread - 通过 CreateRemoteThread 进行 DLL 注入
  - Shellcode - 直接注入 Shellcode（无需 DLL）
  - APC - 异步过程调用注入

- **跨架构支持：** 自动检测目标进程架构（32位/64位），并使用对应的注入器

## 使用方法

1. 可以管理员身份运行 `WindowAffinityTool64.exe`
2. 选择注入方式（推荐 Shellcode）
3. 将 Finder 图标拖拽到目标窗口
4. 确认操作

所有文件需放在同一目录下。

## 编译

需要 MinGW-w64（32位和64位工具链）。

```batch
# 64位
gcc -o WindowAffinityTool64.exe main.c -lgdi32 -lcomctl32 -ladvapi32 -luser32 -ldwmapi -mwindows -municode -O2
gcc -shared -o inject_dll64.dll inject_dll.c -luser32 -municode -O2

# 32位
i686-w64-mingw32-gcc -o WindowAffinityTool32.exe main.c -lgdi32 -lcomctl32 -ladvapi32 -luser32 -ldwmapi -mwindows -municode -O2
i686-w64-mingw32-gcc -shared -o inject_dll32.dll inject_dll.c -luser32 -municode -O2
```

## 系统要求

- Windows 10/11
- 管理员权限（用于进程注入）

## 注意事项

- ⚠️⚠️⚠️***受保护进程禁止注入！！！所造成的系统功能损坏或付费账号封号概不负责***
- 本工具也可以修改自身窗口的显示属性
