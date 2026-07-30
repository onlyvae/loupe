<p align="center">
  <img src="docs/images/loupe-icon.png" alt="Loupe" width="120">
</p>

# Loupe Extended

这是一个基于 [Mysk Loupe](https://github.com/mysk-research/loupe) 二次开发的 iOS / iPadOS 设备信息与安全环境检测工具。

Loupe 会读取第三方 App 能通过公开系统 API 获取的真实数据，并直接展示原始值。你可以借此了解一台 iPhone 会暴露哪些可用于设备指纹识别的信息，以及常见的越狱、代码注入和网络环境特征。

所有检测均在本机完成。除非你主动导出报告，否则数据不会上传、同步或分享。

<p align="center">
  <img src="docs/images/iphone-1.png" alt="Loupe 的被动信号页面" width="200">
  <img src="docs/images/iphone-2.png" alt="Loupe 的权限信号页面" width="200">
  <img src="docs/images/iphone-3.png" alt="Loupe 的设备指纹摘要页面" width="200">
</p>

## 本分支新增与扩展

在上游项目的设备指纹检测能力之外，本分支主要增加了以下内容：

- **越狱痕迹检测**：使用 `lstat`、`access` 和 `open` 检查常见越狱文件及目录。
- **调试器检测**：读取当前进程的 `P_TRACED` 状态，显示 App 是否正被 `ptrace` 类调试器跟踪。
- **DYLD 注入检测**：直接读取当前进程的 `DYLD_INSERT_LIBRARIES`，并检查 App 包和 dyld 共享缓存之外加载的 `.dylib`。即使 dyld 在 App 代码运行前清除了环境变量，也能通过已加载镜像发现注入候选并显示原始路径。已排除系统库 `libobjc-trampolines.dylib` 造成的已知误报。
- **Hook 框架检测**：检查当前进程已加载的动态库，识别 Substrate、Frida、Substitute、libhooker、ElleKit、systemhook 等常见标记。
- **Frida 指标检测**：综合检查 Frida 相关文件与已加载代码、被修改的函数入口，以及异常的可写可执行内存区域。
- **Objective-C Runtime Hook 检测**：检查部分系统方法的实现地址是否落在 Apple 系统库之外。
- **屏幕捕获状态**：实时显示屏幕是否正在录制、镜像或通过 AirPlay 输出。
- **网络环境信息**：展示活动接口、系统返回的网络接口、处于启用状态的接口，以及 HTTP 代理状态和端点。
- **时间与时区信息**：补充当前时间和 WebView 暴露的时区标识符。

安全环境检测属于只读的启发式检测，不会尝试阻止调试、注入或越狱环境。检测结果不应被视为完整的越狱证明或安全审计结论。iOS 沙盒、系统版本、其他合法软件以及工具的隐藏能力都可能造成漏报或误报。崩溃报告中的 `dyld config` 由系统在进程启动早期记录，普通 App 无法通过公开 API 直接读取，因此 DYLD 检测会结合环境变量与已加载镜像进行判断。

## 信号分类

Loupe 按读取成本将信号分为三类：

- **Passive**：无需弹出系统授权提示即可读取，例如设备、系统、显示、电池、网络和安全环境信息。
- **Needs Permission**：需要用户授权，例如联系人、照片、位置、日历和相机。
- **Advanced**：利用公开 API 进行的进阶侧信道读取，例如通过 `canOpenURL` 探测已安装 App、使用隐藏的 `WKWebView` 获取 Canvas / WebGL 指纹，以及通过 Keychain 观察重新安装记录。

## 隐私

- 检测结果仅保存在当前设备上。
- App 不包含账号系统或分析服务。
- 原始值不会被聚合或哈希。
- 只有你主动使用导出功能时，数据才会交给系统分享面板。

## 构建

### 环境要求

- macOS
- Xcode 26 或更高版本
- iOS / iPadOS 16.0 或更高版本，或 macOS 14.0 或更高版本

### 运行项目

1. 克隆仓库并打开 `code/Loupe.xcodeproj`。
2. 将 `code/Config/Signing.local.xcconfig.example` 复制为 `code/Config/Signing.local.xcconfig`。
3. 在本地配置文件中填写自己的 `DEVELOPMENT_TEAM` 和 Bundle Identifier。
4. 在 Xcode 中选择真机或模拟器，然后构建运行。

项目使用 Xcode 的 buildable folders，新建 Swift 文件后无需手动添加到 Build Sources。

### 导出 IPA

完成签名配置后，可在仓库根目录执行：

```sh
./scripts/export-ipa.sh
```

默认产物为 `build/ipa/Loupe.ipa`，并同时复制为 `build/ipa/Loupe.tipa`。脚本支持 `--method app-store`、`--method ad-hoc`、`--method enterprise` 等导出方式；执行 `./scripts/export-ipa.sh --help` 可查看完整参数。

## 项目来源与许可

本项目是 [Mysk Loupe](https://github.com/mysk-research/loupe) 的非官方衍生版本，新增部分由本仓库维护者开发。原项目由 [Mysk](https://mysk.co) 创建。

源代码遵循 [MIT License](LICENSE)。请注意，Loupe 名称、Logo、App 图标、其他图片与设计源文件归 Mysk 所有，不属于 MIT 许可范围。分发自己的构建版本前，请按照许可证说明替换相关品牌素材。

本项目仅用于隐私教育、安全研究和测试。请仅在你拥有或获准测试的设备上使用。
