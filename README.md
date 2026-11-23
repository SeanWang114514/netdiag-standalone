# NetDiag 独立单文件版

把火绒 `NetDiag.exe`（网络诊断/断网修复工具）从火绒安装环境中解耦，打包成**可独立运行的单文件 exe**，并保留原版图标。

> 说明：本项目只做运行时解耦与打包，不涉及任何授权/激活逻辑修改。

## 两个版本

| 文件 | 大小 | 说明 |
|---|---|---|
| `NetDiagStandalone.exe` | ~6.7 MB | **原样打包版**。原封不动内嵌 `NetDiag.exe` + 火绒 DLL + UI 资源，功能逻辑 100% 保真。 |
| `NetDiagStandalone_Decoupled.exe` | ~4.6 MB | **解耦版**。主程序字节不变，但把火绒的 `selfprot.dll`/`usysdiag.dll` 换成自写替身（2 KB 级），去掉 `uactmon.dll`/`libxsse.dll`，不含任何火绒专有代码。 |

两者均为 x64 GUI 单文件，仅依赖 `kernel32.dll`，**自带原版 11 尺寸图标**。

## 运行机制

1. 内嵌 payload 释放到 `%TEMP%\NetDiagStandalone_<pid>_<时间>\`
2. 在该目录启动 `NetDiag.exe`（命令行参数原样透传）
3. 主程序退出后自动清理临时目录

调试时设环境变量 `NETDIAG_KEEP_TEMP=1` 可保留临时目录。

## 依赖分析结论

`NetDiag.exe` 的依赖闭包：

- `DuiLib.dll` — 开源界面库，非火绒本体
- `NetDiag.ui` — 自包含 ZIP 资源包（XML + SVG）
- `usysdiag.dll` — 火绒诊断接口（`vif_get` 等 6 个工厂函数）
- `selfprot.dll` — 火绒自我保护
- `uactmon.dll` / `libxsse.dll` — usysdiag 的传递依赖

逆向发现（解耦版的依据）：

- 整条依赖链无内核驱动/服务依赖，全部为系统 API
- `selfprot!init_selfprot_procedure` 的返回值不被检查
- NetDiag 只调用 `usysdiag!vif_get()` + `vtable[0]()`（初始化，返回 0 即成功）；`vif_sysutils_get` 从未被调用
- 网络修复动作（netsh/ipconfig/DNS）由 NetDiag 自身 `CreateProcess` 执行，不经过火绒库

## 验证状态

- ✅ PE 结构、导出表、vtable 调用链静态验证
- ✅ 内嵌文件与临时释放文件逐字节 SHA256 比对
- ✅ 图标资源（RT_ICON + RT_GROUP_ICON，11 尺寸）已嵌入两个 exe
- ⚠️ 动态启动在开发沙箱中未验证（沙箱拦截子进程创建）；在正常 Windows 桌面环境应可直接运行

## 从源码重建

需要 Go 1.24+（本项目用 `-H=windowsgui` 消除控制台窗口）。

```bash
# 原样打包版：把 payload/ 放进 launcher/ 后
cd launcher && go build -trimpath -ldflags '-s -w -H=windowsgui' -o ../NetDiagStandalone.exe .

# 解耦版：先运行 src/make_stub_dll.py 生成替身 DLL，放进 launcher_b/payload/ 后
cd launcher_b && go build -trimpath -ldflags '-s -w -H=windowsgui' -o ../NetDiagStandalone_Decoupled.exe .
```

图标由 `src/extract_icon.py` 从原版 exe 提取，`src/make_syso.py` 生成 `icon.syso` 供 Go 链接器嵌入。
