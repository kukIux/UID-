# UID Filter / UID 过滤

作者：泷泽。当前版本：0.2.8。

通过过滤指定包的`getpriority(PRIO_USER)`  做到规避检测。

模块面向 arm64、Android 13+、Zygisk API 5，WebUI 支持中文、英文和乌克兰语。过滤仅作用于配置选中的普通应用进程；默认包名为 `com.chunqiunativecheck` 和 `com.chunqiu.appvisibilitydemo`。

## Windows 构建

需要 Python 3.10+ 和 Android NDK `27.3.13750724`。默认从 `%LOCALAPPDATA%/Android/Sdk` 查找 SDK；可用 `ANDROID_SDK_ROOT` / `ANDROID_HOME` 指定 SDK，或用 `ANDROID_NDK_HOME` 直接指定 NDK 根目录。

```powershell
git clone https://github.com/longze777/UID-.git
Set-Location UID-
python tools/uid-seccomp-module/build.py --module-only
```

只构建模块，无需 Java、Gradle 或额外的 Python 包。Zygisk API 5 头文件已随源码提供，构建时会校验其固定 SHA-256。

输出文件：

- `build/0.2.8/cq-uid-seccomp-0.2.8.zip`
- `build/0.2.8/cq-uid-seccomp-0.2.8.zip.sha256`

可用 `--output <目录>` 指定输出目录，或用 `--config <文件>` 指定默认配置。配置首行为 `enabled=1` 或 `enabled=0`，随后每行一个完整包名。省略 `--module-only` 同样只构建模块。

## 安装与配置

使用兼容的模块管理器和 Zygisk 提供程序安装 ZIP，重启后打开模块 WebUI。面板支持开关过滤、添加和移除包名，以及保存并应用配置。配置切换会停止过滤状态发生变化的目标应用，重新打开后生效；不会清除应用数据。

当前操作按钮适配 KernelSU（`me.weishu.kernelsu`）。

0.2.8 修复：在安装过滤器时完成通知连接和句柄交付，修复应用初始化阶段连接提前关闭、子进程规则继承修复未生效的问题。

面板版本号与模块版本保持一致，并加入乌克兰语翻译（感谢 kukIux）。

0.2.7 修复：应用追加 seccomp 规则后，子进程按创建它的线程继承规则，修复父子进程查询返回值不一致的问题。

0.2.6 修复：析构回调改为模块内部登记和清理，避免在 libc 的退出回调表中留下登记痕迹；发布 SO 移除 `atexit` 符号字符串，仅导出 Zygisk 入口。

0.2.5 修复：在支持的平台策略上，保持合并前的 seccomp 指令预算，修复应用可安装过滤规则的额度差异。

0.2.4 修复：合并系统 seccomp 策略时保持原有的 `NoNewPrivs` 状态和过滤器数量，移除模块启动日志。

## 源码

- `tools/uid-seccomp-module/module.cpp`、`filter.h`、`policy.h`：原生模块。
- `tools/uid-seccomp-module/broker.cpp`、`notification.h`、`fork_events.h`：通知处理及子进程规则继承。
- `tools/uid-seccomp-module/panel/`：安装、配置脚本及 WebUI 资源。
- `tools/uid-seccomp-module/build.py`：编译与 ZIP 打包。
- `third_party/zygisk/`：原始头文件、许可声明和来源校验信息。
- `third_party/local_cxa/`：本地析构回调实现，改编自 [5ec1cff/local_cxa_atexit_finalize_impl](https://github.com/5ec1cff/local_cxa_atexit_finalize_impl)。

项目沿用 [Apache-2.0 许可证](LICENSE)；第三方代码保留其原始许可声明，本地析构实现的许可和署名同时收录在安装包的 `legal/` 目录。
