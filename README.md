# Liuli content analysis runner

琉璃壁纸平台的无密钥影子内容分析器。仓库只包含公开工作流与像素分析代码，不包含产品源码、用户数据或长期机器密钥。

GitHub Actions 使用短时 OIDC 身份访问生产机器 API；生产端固定校验本仓库数字 ID、所有者数字 ID、main 分支和工作流引用。工作流先从 Art Institute of Chicago 官方公开领域 API 发现候选，再执行 Pillow 像素分析与 ClamAV 扫描，结果只进入影子账本，自动发布保持关闭。

手动运行：Actions → Liuli content analysis → Run workflow，可选指定 1–1000 的来源页。定时任务每日 UTC 03:40 运行。
