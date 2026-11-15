# 控制台截图

[English](../screenshots/README.md) | **简体中文**

这些 PNG 展示 GovWeave 实际内嵌控制台的英文和简体中文界面，来自使用合成数据的隔离浏览器测试，不是运维人员的正式实例。总览活动使用模拟数据；插件预览与覆盖面板使用临时本机网关和合成上游。名称、计数和发现仅作展示，不是生产测量或合规结论。

即使浏览器语言为中文，控制台也默认英文。语言选择器可切换界面并在本机记住选择，测试验证这两种行为。用户输入的名称及规则包元数据不会被自动翻译。

## 更新截图

按[浏览器测试前提](development.md)准备依赖，执行 `make build` 编译当前网关，再运行：

```sh
node tests/dashboard-smoke.cjs
node tests/plugins-smoke.cjs
```

插件测试默认使用 `bin/govweave`，也可用 `GOVWEAVE_TEST_BINARY` 指定当前构建。测试仅启动本机合成服务，需要本机监听端口和无界面 Chrome，不需要真实上游密钥，也不会产生付费模型调用。

检查生成图片后，按[英文说明中的源文件映射](../screenshots/README.md#refresh)，将六张图片复制到 `docs/screenshots/`。主 README 展示英文截图，中文 README 展示中文截图。

这里只提交经过检查、适合公开的界面截图。原始测试报告、正式实例数据、凭证和私有采集内容不得进入 Git；不要未经内容检查和发布授权就替换为真实已登录实例截图。

框架实操截图于 2026-11-15 由 `tests/plugins-smoke.cjs` 在六包入门目录及两个内部合成版本上拍摄，展示合成 ISO 准备档案，不是已审核组织。视觉检查后，可将最新成功测试的 `framework-selection-en.png` 和 `framework-selection-zh.png` 复制到 `docs/screenshots/`。
