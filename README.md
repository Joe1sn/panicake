# panicake
用于自用的 Windows 内核漏洞/实验/概念验证/研究框架

windows kernel vuln/exp/poc/research framework for selfuse

基于本人研究的，自用版本的 windows 内核漏洞利用/PoC 

A collection of Windows kernel exploits/PoCs, developed for my own research and personal use.

| CVE ID               | Winver                             | Module      | Source                                   |
| -------------------- | ---------------------------------- | ----------- | ---------------------------------------- |
| CVE-2026-40369       | Version 25H2 (OS Build 26200.4946) | ntoskrl.exe | https://github.com/Joe1sn/CVE_2026_40369 |
| CVE-2023-21768       | Version 22H2 (OS Build 22621.1)    | afd.sys     | https://github.com/Joe1sn/CVE_2023_21768 |
| [TODO]CVE_2021_40449 | Version 1809(OS Build 17763.737)   | win32k.sys  | https://github.com/Joe1sn/CVE_2021_40449 |
| [TODO] CVE-2021-1732 | Version 1809(OS Build 17763.737)   | win32k.sys  | https://github.com/Joe1sn/CVE_2021_1732  |
关于分支：

About the branches:

- `main`：开发框架，便于后续的漏洞研究

  `main`: A development framework designed to facilitate ongoing vulnerability research.

- `exploit`：自写的exp迁移

  `exploit`: A repository for my custom-written exploits.
