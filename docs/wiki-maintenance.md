# Wiki 维护指南

站点名称为 **Agent Security Wiki**，中文副标题为“Java AI Agent 运行时安全指南”。修改根目录 `mkdocs.yml` 中的 `site_name`、`site_description` 和首页即可调整名称。

## 本地预览与构建

在仓库根目录执行，需要 Python 3.9+；CI 使用 Python 3.12：

```bash
python3 -m venv .venv-docs
source .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt
python -m mkdocs serve
```

打开 `http://127.0.0.1:8000/`，修改文档后自动重建。修改构建 hook 后重启预览服务。

```bash
python -m mkdocs build --strict
```

生成文件位于 `site/`，不提交到源码仓库。导航遗漏、找不到的文档链接和不存在的锚点都会导致严格构建失败；外部链接可用性不在此检查范围内。文档构建不需要 Java、Maven 或模型 API key。

## 文档来源与导航

- `docs/index.md`：Wiki 首页和阅读路线。
- `README.md`：项目概览与快速运行的唯一来源；构建时生成 `overview.md`，不要手动创建同名源文档。
- `docs/*.md`：现有专题文档，原路径保留，继续支持在 GitHub 中阅读。
- `docs/evidence/`：随站点保留的验证证据。
- `scripts/docs_hooks.py`：读取 README、调整站内相对链接，并仅发布明确列出的五份配置示例。不要将真实部署凭据添加到示例中。
- `mkdocs.yml`：导航、主题、搜索、校验规则。
- `requirements-docs.txt`：固定 MkDocs 和主题版本；间接依赖由 pip 解析，未声明完整依赖锁定。

新增专题后，在 `mkdocs.yml` 的 `nav` 中添加入口。文档之间使用相对 Markdown 链接，例如 `[运行手册](operations.md)`。现有 `../config/` 链接在构建时转换为站内配置路径，源文档不改写。

## GitHub Actions 与 Pages

`.github/workflows/docs.yml` 对文档相关变更自动构建：

| 触发方式 | 行为 |
| --- | --- |
| Pull request | 严格构建并保存 `wiki-site` 制品，不部署 |
| 普通分支 push | 严格构建并保存制品 |
| 默认分支 push | 严格构建、上传 Pages 制品、部署 |
| 手动运行 | 构建所选分支；仅默认分支部署 |

工作流动态读取仓库默认分支，不要求必须叫 `main` 或 `master`。站点地址由 Pages 配置提供，支持项目子路径和已配置的自定义域名。构建权限为 `contents: read`；仅部署作业取得 `pages: write` 和 `id-token: write`。Actions 固定到官方标签对应的提交 SHA，由现有 Dependabot Actions 配置跟踪更新。

首次发布需要仓库管理员完成一次设置：

1. 将文件提交并推送到 GitHub 仓库。
2. 打开 **Settings → Pages → Build and deployment → Source**，选择 **GitHub Actions**。
3. 在 **Actions → Build and deploy Wiki → Run workflow** 选择默认分支运行。
4. 从部署作业的 `github-pages` 环境链接访问网站。

配置与权限要求参见 [GitHub Pages 官方文档](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)。若环境有审批或分支保护，需满足对应规则后才会发布。当前配置文件不代表远端工作流已经执行成功。

本地生成供其他地址托管的版本时可指定正式地址：

```bash
DOCS_SITE_URL=https://example.com/agent-security/ python -m mkdocs build --strict
```

默认地址仅用于本地预览。站点构建的 hook 与配置依据 [MkDocs 配置文档](https://www.mkdocs.org/user-guide/configuration/)。
