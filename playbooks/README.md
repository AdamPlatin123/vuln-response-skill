# playbooks/ · 交件规范

## 命名

`NN-<ecosystem>-<slug>.md`

- `NN`：两位数字，从 01 起，不重复、不复用；
- `ecosystem` ∈ `node` `npm` `go` `python` `python-llm` `php` `pki` `generic`；
- `slug`：小写英文 + 连字符，能看懂即可（`security-release`、`supply-chain`）。

## 流程

```
_草稿_  playbooks/_draft/            ← 交件人在这里写
           │  跑 lint --all 通过
           ▼
_定稿_  playbooks/                   ← Skill工坊 归并、checklist 过一遍后移入
           │  bin/seal.sh
           ▼
        MANIFEST.sha256              ← 报绝对路径 + sha256 给 Lead 注册
```

## 交件必须包含

**frontmatter（9 个字段，缺一打回）**

`id` `title` `ecosystem` `affects` `fixed` `severity` `status` `sources` `updated`

**正文 6 段（顺序固定，缺一打回）**

1. `## 适用版本区间` —— 精确 semver 区间 + 判断命令
2. `## 检测` —— 怎么发现「我用没用」，带命令块 + 命中判据
3. `## 影响判定` —— 利用条件表 + 误报排除
4. `## 修复` —— 止血 → 升级，带命令块
5. `## 验证` —— 怎么证明修好了，带命令块 + 通过标准
6. `## 回退` —— 回退命令 + 回退后风险

## 起稿

```bash
cd /path/to/vuln-response-skill
bash bin/new-playbook.sh 01 node-security-release
# 产出 playbooks/_draft/<NN>-<slug>.md（示例：08-php-runtime）
```

## 交件前自检

```bash
bash bin/lint-playbooks.sh --all      # 必须 exit 0
sha256sum playbooks/_draft/<NN>-*.md    # 报绝对路径 + 这个 hash
```

## 常见打回原因（按出现频率）

| 原因 | 修法 |
|---|---|
| `affects` / `fixed` 空着或写「最新版」 | 写精确区间，如 `>=1.81.16 <1.83.7` |
| 验证段只有 `npm install` 成功，没有功能验证 | 补「通过标准」：版本探测 + 复现用例 + 回归 |
| 没有回退段 | 写清回退命令和回退后暴露面 |
| 引用了二手报道当唯一来源 | 补一手 URL，或降级为「未确认」 |
| 命令里有未说明的 `<>` 占位符 | 换成可跑的命令，或注明变量含义 |
| 把多条 CVE 写成多份 playbook | 归并成一份 + 末尾 `## 条目` 表 |
