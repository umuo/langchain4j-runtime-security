# 工具权限与参数规则

`agent-security-policy` 是独立的 SDK 模块，依赖 core 和 Jackson Core。Agent 已将其打包，并隔离 Jackson 包名；业务应用只需提供策略文件。规则作用于 `TOOL_INPUT`，在已覆盖的执行器入口执行工具前检查；不会回滚此前已经执行的操作。

## 启用与语义

在主 properties 文件设置 `tool.policy.path=tools.json`。绝对路径直接使用，相对路径以主 properties 文件的目录为基准。策略文件必须是合法 UTF-8、最多 1 MiB，启动时加载。格式错误、不支持的字段、缺失文件均使启动失败。

```json
{
  "schemaVersion": 1,
  "maxArgumentChars": 100000,
  "tools": {
    "lookupCustomer": {
      "type": "object",
      "required": ["customerId", "limit"],
      "additionalProperties": false,
      "properties": {
        "customerId": {"type": "string", "enum": ["demo-customer"]},
        "limit": {"type": "integer", "minimum": 1, "maximum": 10}
      }
    }
  }
}
```

这个文件只允许 `lookupCustomer`。工具名精确匹配，区分大小写，不支持通配符。空 `tools` 拒绝所有工具。未知工具返回 `tool-not-allowed`；不要从模型给出的工具描述或参数自动生成可信规则。

`allow.tools` 是独立的可选 properties 白名单，显式空值也拒绝全部工具。`deny.tools` 优先拒绝；多个策略取允许范围的交集，插件不能把先前的拒绝改成允许。没有设置 `tool.policy.path` 时，不启用本模块的结构化检查。

## 支持的规则

这是受限的规则格式，**不是完整 JSON Schema 实现**。对象所有层级都采用闭合字段集合，省略 `additionalProperties` 也会拒绝未知字段；只能显式指定 `false`。未知规则键均为启动错误。

| type | 支持的字段 | 语义 |
| --- | --- | --- |
| `object` | `properties`（必填）、`required`、`additionalProperties` | `required` 默认为空；存在的字段必须通过对应规则；禁止额外字段；工具参数根必须是 object |
| `string` | `enum`、`minLength`、`maxLength`、`equalsContext` | 长度按 Unicode 码点，默认 0～256，最大可配置 1,000,000；枚举解码后精确比较；`equalsContext` 只接受 `tenantId` 或 `principalId`，精确匹配可信身份 |
| `integer` | `enum`、`minimum`、`maximum` | 必须为数值类型且数学上为整数；`1`、`1.0`、`1e0` 等价；不将字符串或布尔值转换为数字 |
| `number` | `enum`、`minimum`、`maximum` | 使用十进制精确比较，边界包含等号；不使用浮点近似判定权限 |
| `boolean` | `enum` | 只允许 JSON true／false，不接受字符串 |
| `array` | `items`（必填）、`minItems`、`maxItems` | 单一元素规则；默认长度 0～64，最大可配置 4096；每个元素都需通过检查 |

`enum` 仅支持标量类型，非空，最多 1024 个值，枚举值本身也必须符合类型与范围。数值范围没有隐含的 Java int／long 上下界，必须依据真实工具签名和业务限制填写；SDK 不自动推导 Java 参数类型或控制累计预算。省略字段只在该字段未列入 `required` 时允许；显式 null 不符合以上任何类型。

不支持 `$ref`、远程 schema、`pattern`、`format`、`oneOf`、默认值插入、类型强制转换或脚本。若配置这些规则会失败，不会假装完成验证。需要固定 URL／资源 ID 时可使用精确枚举；这不提供 DNS、重定向、文件系统路径或资源端鉴权保证。

## 解析与内容检测

根对象还支持可选 `permissions`，将工具名映射到所需权限字符串数组，例如 `"permissions":{"lookup":["customers:read"]}`。工具必须已在 `tools` 定义，数组非空且无重复，调用上下文必须包含全部权限。权限标识限 1～128 位字母、数字或 `@._:-`。未配置权限的工具不隐式要求任何权限。

配置权限或任意嵌套 `equalsContext` 的工具必须有可信上下文，即使对应参数是可选且本次未出现。`equalsContext` 不自动将字段变为必填，需要同时列入所在对象的 `required`。不能从工具参数构造身份。完整例子见 [身份策略](../config/context-tool-policy-example.json) 和 [应用接入](security-context.md)。

`maxArgumentChars` 限制原始参数的 Java UTF-16 长度，默认 100,000，范围 1～1,000,000；主 `max.text.chars` 显式设置后仍会先检查原文；未设置或空值不限制主文本长度，但不关闭这里的 `maxArgumentChars`。参数 JSON 深度最多 16、节点最多 20,000、字段名最多 1024；数字词法长度最多 128、精度最多 128 位、十进制 scale 绝对值最多 1024。策略编译深度也受限。上述是拒绝阈值，不是应用总堆内存配额。

重复字段（包括 `limit` 与 `l\u0069mit`）、多个顶层值、注释、NaN／Infinity、未配对 UTF-16 surrogate 均拒绝。无参数调用的 null、空字符串和纯空白被视为 `{}`，但原始长度仍必须符合上限；有必填参数的工具仍会拒绝这种空对象。

Agent 先应用原文规则，再检查结构化策略，对通过结构检查的解码键和字符串应用同一 `LocalPolicy`。例如 `deny.text=secret` 也能拒绝参数中的 `s\u0065cret`。字符串检查不对任意 Base64、URL 编码或自然语言改写做递归解码，不等于提示注入分类器；模型输出与工具结果的任意 JSON 也不会自动按此规则解析。

所有检测都在执行前完成。可识别错误为：

| ruleId | 含义 |
| --- | --- |
| `tool-not-allowed` | 工具未在允许集合中 |
| `tool-arguments-limit` | 原始参数超过本策略上限 |
| `invalid-tool-arguments` | JSON 不合法、存在歧义或超过解析限制 |
| `tool-argument-policy` | 解码后的参数不符合规则 |
| `missing-security-context` | 工具需要可信身份，但事件没有身份快照 |
| `permission-denied` | 上下文未包含该工具要求的全部权限 |
| `denied-text` | 解码后的字符串命中本地内容规则 |

错误与内置审计只记录固定原因，不输出参数、字段路径、枚举成员或解析器异常文本。审计决策不代表实际工具执行成功。

## 独立 SDK 用法

```java
Properties properties = new Properties();
properties.setProperty("deny.text", "secret");
LocalPolicy local = new LocalPolicy(properties);
ToolPolicy tools = ToolPolicy.fromPath(Path.of("tools.json"), local);
try (PolicyEngine engine = new PolicyEngine(List.of(local, tools), auditSink)) {
    engine.check(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT,
            "lookupCustomer", "{\"customerId\":\"demo-customer\",\"limit\":2}"));
    // 只有返回成功之后才调用实际工具；不要吞掉拒绝后继续执行。
}
```

`auditSink` 需由调用方提供；Agent 接入方式会自动使用其配置的有界审计。`ToolPolicy` 不修改传入数据，实例可在线程之间共享，执行受 `PolicyEngine` 的检测超时／并发限制约束。

枚举是部署级静态约束；`permissions` 与 `equalsContext` 则使用应用提供的身份快照。同一文件允许的客户 ID，或与上下文相同的 tenantId，都不能证明任意资源属于该租户；资源端仍需校验客户／文件等真实归属。SDK 不查询业务数据库、不自动撤销已发出的身份快照，也不替代应用认证。
