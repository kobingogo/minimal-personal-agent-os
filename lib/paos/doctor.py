"""5-dimension read-only health, context-bloat, and cross-harness security posture auditor."""

from __future__ import annotations

from collections import Counter
import glob
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .audit import paos_home, scan_text_for_secrets
from .harnesses import list_skills, scan_matrix
from .sync_bus import scan_unpromoted_tags


class Finding:
    def __init__(self, level: str, dimension: str, message: str, fix: str = "") -> None:
        self.level = level  # PASS | WARN | FAIL
        self.dimension = dimension
        self.message = message
        self.fix = fix

    def to_dict(self) -> Dict[str, str]:
        return {
            "level": self.level,
            "dimension": self.dimension,
            "message": self.message,
            "fix": self.fix,
        }


def _expand_user_path(path_str: str, home: Path) -> Path:
    s = path_str.strip()
    if s == "~":
        return home
    if s.startswith("~/"):
        return home / s[2:]
    if s.startswith("$HOME/"):
        return home / s[6:]
    if s.startswith("${HOME}/"):
        return home / s[8:]
    return Path(os.path.expanduser(s))


def _scan_settings_local_for_secrets(path: Path) -> List[str]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text_for_secrets(text)


def run_doctor(workspace: Optional[Path] = None, home_dir: Optional[Path] = None) -> Dict[str, Any]:
    home = paos_home(home_dir)
    ws = (workspace or Path.cwd()).resolve()
    findings: List[Finding] = []

    # =========================================================================
    # Dimension 1: Cross-Harness Context & Memory Bloat Audit
    # =========================================================================
    sk = list_skills(home)
    mat = scan_matrix(home)
    active_n = sk["active_count"]
    parked_n = sk["parked_count"]
    broken_n = mat["totals"]["broken_symlinks"]
    est_tok = sk["estimated_active_tokens"]

    if broken_n > 0:
        findings.append(
            Finding(
                "WARN",
                "context",
                f"五大客户端中检测到 {broken_n} 个失效技能软链接",
                "运行 `paos clean` 或 `paos adopt` 自动治愈/隔离失效软链",
            )
        )
    if active_n > 15:
        findings.append(
            Finding(
                "WARN",
                "context",
                f"常驻用户 Skill 过多（Claude 当前 {active_n} 个，预估启动占用 ~{est_tok} Token；已停放 {parked_n} 个）",
                "先运行 `paos adopt` 建立一级真源，再运行 `paos use minimal` 按场景切档（避免单端挪目录引发断链）",
            )
        )
    else:
        findings.append(
            Finding(
                "PASS",
                "context",
                f"常驻用户 Skill 数量克制（启用 {active_n} 个，预计 ~{est_tok} Token；skills-off 停放 {parked_n} 个）",
            )
        )

    claude_state_json = home / ".claude.json"
    if claude_state_json.is_file():
        sz_kb = claude_state_json.stat().st_size / 1024.0
        if sz_kb > 40:
            findings.append(
                Finding(
                    "WARN",
                    "context",
                    f"~/.claude.json 客户端状态文件膨胀 ({sz_kb:.1f} KB > 40 KB)，积压旧项目缓存易拖慢启动",
                    "运行 `paos clean --prune-claude-state` 自动备份并清理已删除项目的陈旧缓存",
                )
            )

    for rel_label, p, limit_kb in [
        ("~/.claude/CLAUDE.md", home / ".claude" / "CLAUDE.md", 12),
        ("~/.codex/AGENTS.md", home / ".codex" / "AGENTS.md", 12),
        ("~/.gemini/GEMINI.md", home / ".gemini" / "GEMINI.md", 16),
        ("Workspace CLAUDE.md", ws / "CLAUDE.md", 12),
        ("Workspace AGENTS.md", ws / "AGENTS.md", 12),
    ]:
        if p.is_file():
            sz_kb = p.stat().st_size / 1024.0
            if sz_kb > limit_kb:
                findings.append(
                    Finding(
                        "WARN",
                        "context",
                        f"{rel_label} 体积偏大 ({sz_kb:.1f} KB > {limit_kb} KB 建议上限)，每次启动均会产生上下文税",
                        "将低频细节下沉到 topics/ 或按需加载的 SKILL.md 中",
                    )
                )

    raw_mem_candidates = [
        ws / "memory" / "MEMORY.md",
        home / ".paos" / "brain" / "memory" / "MEMORY.md",
    ]
    proj_glob = glob.glob(str(home / ".claude" / "projects" / "*" / "memory" / "MEMORY.md"))
    raw_mem_candidates.extend(Path(x) for x in proj_glob)

    seen_mem: set[Path] = set()
    mem_candidates: List[Path] = []
    for mp in raw_mem_candidates:
        if mp.is_file():
            rp = mp.resolve()
            if rp not in seen_mem:
                seen_mem.add(rp)
                mem_candidates.append(mp)

    over_cliff: List[str] = []
    for mp in mem_candidates:
        try:
            raw_bytes = mp.read_bytes()
            line_cnt = len(raw_bytes.decode("utf-8", errors="replace").splitlines())
            kb = len(raw_bytes) / 1024.0
            if line_cnt > 200 or kb > 25.0:
                over_cliff.append(f"{mp.parent.parent.name}/MEMORY.md ({line_cnt} 行, {kb:.1f}KB)")
        except OSError:
            pass

    if over_cliff:
        findings.append(
            Finding(
                "WARN",
                "context",
                f"发现 {len(over_cliff)} 份 MEMORY.md 超出 200 行/25KB 自动截断红线：{', '.join(over_cliff[:3])}",
                "主 MEMORY.md 仅保留 1 行 1 指针，详细内容移入 topics/*.md",
            )
        )
    else:
        findings.append(Finding("PASS", "context", "所有已扫描 MEMORY.md 均控制在 200 行 / 25KB 截断线以内"))

    # =========================================================================
    # Dimension 2: OS Sandbox & Permission Hardening
    # =========================================================================
    settings_path = home / ".claude" / "settings.json"
    settings_obj: Dict[str, Any] = {}
    settings_loaded = False
    if not settings_path.is_file():
        findings.append(
            Finding(
                "FAIL",
                "sandbox",
                "未检测到 ~/.claude/settings.json，当前终端 Agent 处于无沙盒裸奔状态",
                "运行 `paos harden --all` 一键部署沙盒、权限锁与防呆钩子",
            )
        )
    else:
        try:
            parsed_settings = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(parsed_settings, dict):
                findings.append(
                    Finding("FAIL", "sandbox", "~/.claude/settings.json 顶层必须是 JSON 对象", "修复 JSON 或运行 `paos harden`")
                )
            else:
                settings_obj = parsed_settings
                settings_loaded = True
        except json.JSONDecodeError as exc:
            findings.append(
                Finding("FAIL", "sandbox", f"~/.claude/settings.json JSON 语法损坏: {exc}", "修复 JSON 或运行 `paos rollback`")
            )

    if settings_loaded:
        sb = settings_obj.get("sandbox") or {}
        if not isinstance(sb, dict) or not sb.get("enabled"):
            findings.append(
                Finding("FAIL", "sandbox", "未开启 OS 级沙盒 (`sandbox.enabled != true`)", "运行 `paos harden --all`")
            )
        else:
            escapes: List[str] = []
            if sb.get("allowUnsandboxedCommands", True) is not False:
                escapes.append("allowUnsandboxedCommands 未设为 false（存在默认逃生舱）")
            if sb.get("failIfUnavailable", False) is not True:
                escapes.append("failIfUnavailable 未设为 true（缺依赖时会静默降级）")
            if escapes:
                findings.append(
                    Finding("FAIL", "sandbox", "沙盒存在逃生隐患：" + "；".join(escapes), "运行 `paos harden --all` 自动补齐")
                )
            else:
                findings.append(Finding("PASS", "sandbox", "OS 级沙盒已启用且已封死默认逃生舱"))

        fs = (sb.get("filesystem") if isinstance(sb, dict) else None) or {}
        deny_read = " ".join(str(x) for x in (fs.get("denyRead") or []))
        deny_write = " ".join(str(x) for x in (fs.get("denyWrite") or []))
        missing_dr = [k for k in (".ssh", ".aws", ".env", ".paos/config.json") if k not in deny_read]
        if missing_dr:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    f"sandbox.filesystem.denyRead 未完整覆盖敏感凭据路径：{', '.join(missing_dr)}",
                    "运行 `paos harden` 补齐 denyRead 列表",
                )
            )
        if ".claude" not in deny_write:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    "sandbox.filesystem.denyWrite 未锁死 ~/.claude/**（Agent 子进程可篡改自身护栏）",
                    "运行 `paos harden` 锁定控制面目录",
                )
            )

        perms_deny = " ".join(str(x) for x in ((settings_obj.get("permissions") or {}).get("deny") or []))
        if "Read(.env" not in perms_deny or "Write(~/.claude" not in perms_deny or "Edit(~/.claude" not in perms_deny:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    "permissions.deny 未完整封禁内置 Read(.env) 或 Write/Edit(~/.claude/**) 工具",
                    "运行 `paos harden` 同步写入 permissions.deny",
                )
            )
        else:
            findings.append(Finding("PASS", "sandbox", "内置 Read(.env) 与控制面写权限双锁已生效"))

    if (home / ".codex").is_dir():
        codex_guard = home / ".codex" / "rules" / "paos-guardrails.rules"
        if codex_guard.is_file():
            findings.append(Finding("PASS", "sandbox", "Codex Starlark 命令门禁 (paos-guardrails.rules) 已就位"))
        else:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    "检测到本机已安装 Codex (~/.codex)，但尚未部署 Starlark 命令门禁规则",
                    "运行 `paos harden --all` 生成并校验 paos-guardrails.rules",
                )
            )

    # =========================================================================
    # Dimension 3: Hooks Schema & Fail-Closed Validation
    # =========================================================================
    hooks_cfg = settings_obj.get("hooks") if isinstance(settings_obj, dict) else None
    if not isinstance(hooks_cfg, dict) or not hooks_cfg.get("PreToolUse"):
        findings.append(
            Finding(
                "WARN",
                "hooks",
                "未配置全局 PreToolUse 防呆拦截钩子",
                "运行 `paos harden` 部署 pre_tool_gate.py",
            )
        )
    else:
        schema_errors: List[str] = []
        cmd_paths: List[Tuple[Path, bool]] = []
        has_paos_gate = False
        for event_name, matchers in hooks_cfg.items():
            if not isinstance(matchers, list):
                schema_errors.append(f"{event_name} 必须是数组")
                continue
            for i, m_obj in enumerate(matchers):
                if not isinstance(m_obj, dict) or "hooks" not in m_obj or not isinstance(m_obj.get("hooks"), list):
                    schema_errors.append(
                        f"{event_name}[{i}] 缺少三层嵌套 `\"hooks\": [...]` 数组（平铺写 command 会静默失效！）"
                    )
                    continue
                for h in m_obj["hooks"]:
                    if isinstance(h, dict) and h.get("type") == "command" and h.get("command"):
                        cmd_raw = str(h["command"]).strip()
                        if "pre_tool_gate" in cmd_raw:
                            has_paos_gate = True
                        try:
                            toks = shlex.split(cmd_raw)
                        except ValueError:
                            toks = cmd_raw.split()
                        if not toks:
                            continue
                        first = toks[0]
                        base_bin = os.path.basename(first)
                        if base_bin in ("python", "python3", "bash", "sh", "zsh", "node"):
                            if any(t in ("-c", "-m", "-e") for t in toks[1:3]):
                                continue  # Inline script/module invocation — no file path to stat
                            script_args = [t for t in toks[1:] if not t.startswith("-")]
                            if script_args:
                                exp = _expand_user_path(script_args[0], home)
                                if not str(exp).startswith("$"):
                                    cmd_paths.append((exp, False))
                        else:
                            exp = _expand_user_path(first, home)
                            if str(exp).startswith("$"):
                                continue
                            if "/" in str(exp):
                                cmd_paths.append((exp, True))
                            elif not shutil.which(first):
                                cmd_paths.append((Path(first), True))

        if schema_errors:
            findings.append(
                Finding("FAIL", "hooks", "Hooks Schema 错误：" + "；".join(schema_errors), "改为三层嵌套结构或运行 `paos harden`")
            )
        else:
            missing_exec = [
                str(p)
                for p, need_x in cmd_paths
                if not (p.is_file() and (os.access(p, os.X_OK) if need_x else True))
            ]
            if missing_exec:
                findings.append(
                    Finding(
                        "FAIL",
                        "hooks",
                        f"钩子脚本不存在或缺少可执行权限 (+x)：{', '.join(missing_exec)}",
                        "运行 `paos harden` 重新部署并赋权",
                    )
                )
            elif not has_paos_gate:
                findings.append(
                    Finding(
                        "WARN",
                        "hooks",
                        "PreToolUse 已存在自定义钩子，但尚未挂载 PAOS `pre_tool_gate.py` 词法防呆门禁",
                        "运行 `paos harden` 非破坏性追加门禁钩子",
                    )
                )
            else:
                findings.append(Finding("PASS", "hooks", "Hooks 三层嵌套 Schema 合法且目标脚本均可执行"))

        if "Stop" in hooks_cfg:
            findings.append(
                Finding(
                    "WARN",
                    "hooks",
                    "检测到用户级全局配置了 Stop 钩子（易在普通问答中误触发）",
                    "建议将 Stop 钩子仅放在具体代码仓 .claude/settings.json 并配合 stop_verify.py 熔断器",
                )
            )

    # =========================================================================
    # Dimension 4: Secret Leak Surface Defense
    # =========================================================================
    env = os.environ.copy()
    env["HOME"] = str(home)
    global_excl = ""
    try:
        res = subprocess.run(
            ["git", "config", "--global", "--get", "core.excludesfile"],
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
        )
        if res.returncode == 0:
            global_excl = res.stdout.strip()
    except Exception:
        pass

    global_locked = False
    if global_excl:
        excl_path = _expand_user_path(global_excl, home)
        if excl_path.is_file() and "settings.local.json" in excl_path.read_text(encoding="utf-8", errors="replace"):
            global_locked = True

    if not global_locked:
        findings.append(
            Finding(
                "WARN",
                "secrets",
                "全局 gitignore (`core.excludesfile`) 尚未排除 `.claude/settings.local.json`（防范本地自动批准命令中的凭据误提交 Git）",
                "运行 `paos harden` 自动写入全局 gitignore",
            )
        )
    else:
        findings.append(Finding("PASS", "secrets", "全局 gitignore 已锁死 `.claude/settings.local.json`"))

    for candidate in (ws / ".claude" / "settings.local.json", home / ".claude" / "settings.local.json"):
        secret_hits = _scan_settings_local_for_secrets(candidate)
        if secret_hits:
            findings.append(
                Finding(
                    "FAIL",
                    "secrets",
                    f"{candidate} 中检出 {len(secret_hits)} 处疑似明文内联凭据（{secret_hits[0]}）",
                    "立即打开该文件删除含明文密码/Token 的自动批准规则并轮换泄露凭据",
                )
            )

    if (ws / "Dockerfile").is_file() and not (ws / ".dockerignore").is_file():
        findings.append(
            Finding(
                "WARN",
                "secrets",
                "当前工作区存在 Dockerfile 但缺少 .dockerignore（镜像构建可能把 .env 或 .claude 打包泄露）",
                "添加 .dockerignore 排除 `.env*` 与 `.claude/`",
            )
        )

    # =========================================================================
    # Dimension 5: Learnings Evolution Loop
    # =========================================================================
    shared_learn = home / ".paos" / "brain" / "memory" / "learnings.md"
    local_learn = ws / "memory" / "learnings.md"
    learn_file = local_learn if local_learn.is_file() else shared_learn

    if learn_file.is_file():
        counts_tag = scan_unpromoted_tags(learn_file)
        recurring = [f"{t}({c}次)" for t, c in counts_tag.most_common() if c >= 2]
        if recurring:
            findings.append(
                Finding(
                    "WARN",
                    "evolution",
                    f"learnings.md 中有复发纠偏待晋升：{', '.join(recurring)}",
                    "运行 `paos promote` 审阅复发坑点并晋升为确定性脚本/钩子，随后运行 `paos promote --apply` 归档",
                )
            )
        else:
            findings.append(Finding("PASS", "evolution", "learnings.md 无积压的重复未晋升纠偏"))

    score = 100
    counts = Counter(f.level for f in findings)
    score -= counts["FAIL"] * 22
    score -= counts["WARN"] * 8
    score = max(0, min(100, score))

    return {
        "score": score,
        "workspace": str(ws),
        "home": str(home),
        "summary": {
            "pass": counts["PASS"],
            "warn": counts["WARN"],
            "fail": counts["FAIL"],
        },
        "skills": {
            "active": active_n,
            "parked": parked_n,
            "broken": broken_n,
            "estimated_tokens": est_tok,
        },
        "findings": [f.to_dict() for f in findings],
    }
