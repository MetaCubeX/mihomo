---
name: Bug report
about: Create a report to help us improve
title: "[Bug]"
labels: ''
assignees: ''

---

<!--
感谢你向 Clash Core 提交 issue！
在提交之前，请确认：

- [ ] 如果你可以自己 debug 并解决的话，提交 PR 吧！
- [ ] 我已经在 [Issue Tracker](……/) 中找过我要提出的问题
- [ ] 我已经使用 dev 分支版本测试过，问题依旧存在
- [ ] 我已经仔细看过 [Documentation](https://github.com/Dreamacro/clash/wiki/) 并无法自行解决问题
- [ ] 这是 Clash 核心的问题，并非我所使用的 Clash 衍生版本（如 OpenClash、KoolClash 等）的特定问题

请注意，如果你并没有遵照这个 issue template 填写内容，我们将直接关闭这个 issue。

Thanks for opening an issue towards the Clash core!
But before so, please do the following checklist:

- [ ] Is this something you can **debug and fix**? Send a pull request! Bug fixes and documentation fixes are welcome.
- [ ] I have searched on the [issue tracker](……/) for a related issue.
- [ ] I have tested using the dev branch, and the issue still exists.
- [ ] I have read the [documentation](https://github.com/Dreamacro/clash/wiki/) and was unable to solve the issue
- [ ] This is an issue of the Clash core *per se*, not to the derivatives of Clash, like OpenClash or KoolClash

Please understand that we close issues that fail to follow this issue template.
-->

------------------------------------------------------------------

<!-- 
请附上任何可以帮助我们解决这个问题的信息，如果我们收到的信息不足，我们将对这个 issue 加上 *Needs more information* 标记并在收到更多资讯之前关闭 issue。
Make sure to add **all the information needed to understand the bug** so that someone can help. If the info is missing we'll add the 'Needs more information' label and close the issue until there is enough information.
-->

### Clash config
<!--
在下方附上 Clash core 脱敏后配置文件的内容
Paste the Clash core configuration below.
-->
<details>
  <summary>config.yaml</summary>

```yaml
……
```

</details>

### Clash log
<!--
在下方附上 Clash Core 的日志，log level 使用 DEBUG
Paste the Clash core log below with the log level set to `DEBUG`.
-->
```
……
```

### 环境 Environment

* 操作系统 (the OS that the Clash core is running on)
……
* 网路环境或拓扑 (network conditions/topology)
……
* iptables，如果适用 (if applicable)
……
* ISP 有没有进行 DNS 污染 (is your ISP performing DNS pollution?)
……
* 其他 (any other information that would be useful)
……

### 说明 Description

<!--
请详细、清晰地表达你要提出的论述，例如这个问题如何影响到你？你想实现什么功能？
-->

### 重现问题的具体布骤 Steps to Reproduce

1. [First Step]
2. [Second Step]
3. ……

**我预期会发生……？**
<!-- **Expected behavior:** [What you expected to happen] -->

**实际上发生了什么？**
<!-- **Actual behavior:** [What actually happened] -->

### 可能的解决方案 Possible Solution
<!-- 此项非必须，但是如果你有想法的话欢迎提出。 -->
<!-- Not obligatory, but suggest a fix/reason for the bug, -->
<!-- or ideas how to implement the addition or change -->

### 更多信息 More Information
