# Mini 网站三人（仅 website_only 读）

花名册：司马懿、曹操、分身。不要拉郭嘉/曹冲/曹仁/刘晔/于禁/典韦，不要本地双容器。网站碰到验证码/WAF 不因此创建曹冲。

开局创建司马懿+曹操。司马懿打获准 URL：先活面、先差分，不空扫。曹操独立复现再定性。分身步 11 到场先交出卷判决（同分身卡，2026-10-07 起）再排版。

用户没给 URL、只给名称/企业：先资产搜集（信封 `designated_asset_site`），归属确认后再按站开任务。

视觉、闭环、凭据、CORS 同 SKILL。网站没有郭嘉：司马懿交第一份能力记录后跑一次 `hard_gate.py --phase env`（跳过双拓扑三枪，只查 `in_run`）。**不跳过 JS 采集**：司马懿必须交 `09-si-ma-yi/js-collection.json`（`files_scanned>=1`、清单非空；有混淆三件 true）。
- **混淆 bundle 先程序化解包**（禁硬啃乱码）：`py -3 scripts/js_unpack.py --root <前端目录> --out 09-si-ma-yi`（或 `--bundle <单个>`）；三份机械账与运行态 hook 口径认 SKILL「前端 JS」与 gates「混淆解包三份账」。
- `verify`/`close` 照跑：复杂链真录像、正位 8 块 finding、Origin+ACAO 的 `cors-audit/`、credential_scan 必须 clean。
- close 要司马懿+曹操+分身目录，**不要**因为网站去要曹冲。不因网站跳过这几条。
