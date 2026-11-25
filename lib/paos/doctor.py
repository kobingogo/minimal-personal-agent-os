"""5-dimension read-only health, context-bloat, and security posture auditor."""

from __future__ import annotations

from collections import Counter
import glob
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List

from .skills import list_skills

INLINE_SECRET_PATTERNS = [
    ("OpenAI/Anthropic/API Key", re.compile(r"\bsk-[a-zA-Z0-9_-]{16,}")),
    ("GitHub PAT", re.compile(r"\b(ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})")),
    ("Google API Key", re.compile(r"\bAIza[a-zA-Z0-9_-]{20,}")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[a-zA-Z0-9-]{15,}")),
    ("Database URI Password", re.compile(r"\b(postgres|postgresql|mysql|mongodb|redis)://[^/\s:@]+:[^/\s@]+@")),
    ("Inline Secret Assignment", re.compile(r"\b(PGPASSWORD|PASSWORD|API_KEY|AUTH_TOKEN|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*['\"]?[^\s'\"]{4,}", re.I)),
]

TAG_RE = re.compile(r"\[tag:([a-zA-Z0-9_-]+)\]")


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


def _expand_user(path_str: str, home: Path) -> Path:
    if path_str.startswith("~/"):
        return home / path_str[2:]
    return Path(os.path.expanduser(path_str))


def _scan_settings_local_for_secrets(path: Path) -> List[str]:
    """Scan a settings.local.json file for inline secrets WITHOUT returning secret values."""
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    hits: List[str] = []
    for idx, line in enumerate(text.splitlines(), 1):
        for label, pat in INLINE_SECRET_PATTERNS:
            if pat.search(line):
                hits.append(f"第 {idx} 行命中疑似「{label}」（内容已脱敏隐藏）")
                break
    return hits


def run_doctor(workspace: Path | None = None, home_dir: Path | None = None) -> Dict[str, Any]:
    home = home_dir or Path.home()
    ws = (workspace or Path.cwd()).resolve()
    findings: List[Finding] = []

    # =========================================================================
    # Dimension 1: Context & Memory Bloat Audit
    # =========================================================================
    sk = list_skills(home)
    active_n = sk["active_count"]
    parked_n = sk["parked_count"]
    broken_n = sk["broken_active_count"]
    est_tok = sk["estimated_active_tokens"]

    if broken_n > 0:
        findings.append(
            Finding(
                "WARN",
                "context",
                f"~/.claude/skills 中存在 {broken_n} 个失效软链接",
                "运行 `paos skills clean-broken` 自动移入 skills-off/",
            )
        )
    if active_n > 15:
        findings.append(
            Finding(
                "WARN",
                "context",
                f"常驻用户 Skill 过多（当前 {active_n} 个，预估启动占用 ~{est_tok} Token；已停放 {parked_n} 个）",
                "运行 `paos skills list` 或 `paos skills profile minimal` 仅保留 <=10 个高频主力",
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

    # Check ~/.claude.json state bloat separately from prompt rule files
    claude_state_json = home / ".claude.json"
    if claude_state_json.is_file():
        sz_kb = claude_state_json.stat().st_size / 1024.0
        if sz_kb > 40:
            findings.append(
                Finding(
                    "WARN",
                    "context",
                    f"~/.claude.json 客户端状态文件膨胀 ({sz_kb:.1f} KB > 40 KB)，积压旧项目缓存易拖慢启动",
                    "清理 ~/.claude.json 中已废弃的 projects 历史条目与失效 MCP 记录",
                )
            )

    # Check shared ~/.agents/skills & ~/.codex/skills broken symlinks
    for label, extra_dir in [("~/.agents/skills", home / ".agents" / "skills"), ("~/.codex/skills", home / ".codex" / "skills")]:
        if extra_dir.is_dir():
            entries = [n for n in os.listdir(extra_dir) if not n.startswith(".")]
            dead = [n for n in entries if (extra_dir / n).is_symlink() and not (extra_dir / n).exists()]
            if dead:
                findings.append(
                    Finding(
                        "WARN",
                        "context",
                        f"{label} 中存在 {len(dead)} 个失效软链接（共 {len(entries)} 项）",
                        f"清理失效链接: {', '.join(dead[:5])}",
                    )
                )

    # Check global rule files bloat (actual upfront LLM token tax)
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

    # Check MEMORY.md 200-line / 25KB hard cliff across workspace & ~/.claude/projects
    mem_candidates = [ws / "memory" / "MEMORY.md"]
    proj_glob = glob.glob(str(home / ".claude" / "projects" / "*" / "memory" / "MEMORY.md"))
    mem_candidates.extend(Path(x) for x in proj_glob)

    over_cliff: List[str] = []
    for mp in mem_candidates:
        if mp.is_file():
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
        findings.append(
            Finding("PASS", "context", "所有已扫描 MEMORY.md 均控制在 200 行 / 25KB 截断线以内")
        )

    # =========================================================================
    # Dimension 2: OS Sandbox & Permission Hardening
    # =========================================================================
    settings_path = home / ".claude" / "settings.json"
    settings_obj: Dict[str, Any] = {}
    if not settings_path.is_file():
        findings.append(
            Finding(
                "FAIL",
                "sandbox",
                "未检测到 ~/.claude/settings.json，当前终端 Agent 处于无沙盒裸奔状态",
                "运行 `paos harden` 一键部署沙盒、权限锁与防呆钩子",
            )
        )
    else:
        try:
            settings_obj = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(
                Finding("FAIL", "sandbox", f"~/.claude/settings.json JSON 语法损坏: {exc}", "修复 JSON 或运行 `paos rollback`")
            )
            settings_obj = {}

    if settings_obj:
        sb = settings_obj.get("sandbox") or {}
        if not isinstance(sb, dict) or not sb.get("enabled"):
            findings.append(
                Finding("FAIL", "sandbox", "未开启 OS 级沙盒 (`sandbox.enabled != true`)", "运行 `paos harden`")
            )
        else:
            escapes: List[str] = []
            if sb.get("allowUnsandboxedCommands", True) is not False:
                escapes.append("allowUnsandboxedCommands 未设为 false（存在默认逃生舱）")
            if sb.get("failIfUnavailable", False) is not True:
                escapes.append("failIfUnavailable 未设为 true（缺依赖时会静默降级）")
            if escapes:
                findings.append(
                    Finding("FAIL", "sandbox", "沙盒存在逃生隐患：" + "；".join(escapes), "运行 `paos harden` 自动补齐")
                )
            else:
                findings.append(Finding("PASS", "sandbox", "OS 级沙盒已启用且已封死默认逃生舱"))

        fs = (sb.get("filesystem") if isinstance(sb, dict) else None) or {}
        deny_read = " ".join(str(x) for x in (fs.get("denyRead") or []))
        deny_write = " ".join(str(x) for x in (fs.get("denyWrite") or []))
        missing_dr = [k for k in (".ssh", ".aws", ".env") if k not in deny_read]
        if missing_dr:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    f"sandbox.filesystem.denyRead 未覆盖敏感路径：{', '.join(missing_dr)}",
                    "运行 `paos harden` 补齐 denyRead 列表",
                )
            )
        if ".claude" not in deny_write:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    "sandbox.filesystem.denyWrite 未锁死 ~/.claude/**（Agent 子进程可篡改自身护栏）",
                    "运行 `paos harden` 锁定 ~/.claude/**",
                )
            )

        perms_deny = " ".join(str(x) for x in ((settings_obj.get("permissions") or {}).get("deny") or []))
        if "Read(.env" not in perms_deny:
            findings.append(
                Finding(
                    "WARN",
                    "sandbox",
                    "permissions.deny 未封禁内置 Read(.env) 工具（OS 沙盒仅约束 Shell 子进程，管不到内置 Read）",
                    "运行 `paos harden` 同步写入 permissions.deny",
                )
            )
        else:
            findings.append(Finding("PASS", "sandbox", "内置 Read(.env) 与 ~/.claude 写权限双锁已生效"))

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
        cmd_paths: List[Path] = []
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
                        raw_cmd = str(h["command"]).strip().split()[0]
                        if not raw_cmd.startswith("$"):
                            cmd_paths.append(_expand_user(raw_cmd, home))

        if schema_errors:
            findings.append(
                Finding("FAIL", "hooks", "Hooks Schema 错误：" + "；".join(schema_errors), "改为三层嵌套结构或运行 `paos harden`")
            )
        else:
            missing_exec = [str(p) for p in cmd_paths if not (p.is_file() and os.access(p, os.X_OK))]
            if missing_exec:
                findings.append(
                    Finding(
                        "FAIL",
                        "hooks",
                        f"钩子脚本不存在或缺少可执行权限 (+x)：{', '.join(missing_exec)}",
                        "运行 `paos harden` 重新部署并赋权",
                    )
                )
            else:
                findings.append(Finding("PASS", "hooks", "Hooks 三层嵌套 Schema 合法且目标脚本均可执行"))

        if "Stop" in hooks_cfg:
            findings.append(
                Finding(
                    "WARN",
                    "hooks",
                    "检测到用户级全局配置了 Stop 钩子（易在普通问答中误触发或造成重试死循环）",
                    "建议将 Stop 钩子仅放在具体代码仓 .claude/settings.json 并使用 stop_verify.py 熔断器",
                )
            )

    # =========================================================================
    # Dimension 4: Secret Leak Surface (Apiiro & PixelLeak Defense)
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
        excl_path = _expand_user(global_excl, home)
        if excl_path.is_file():
            content = excl_path.read_text(encoding="utf-8", errors="replace")
            if "settings.local.json" in content:
                global_locked = True

    if not global_locked:
        findings.append(
            Finding(
                "WARN",
                "secrets",
                "全局 gitignore (`core.excludesfile`) 尚未锁死 `.claude/settings.local.json`（防范 2026-11 Apiiro 明文泄密）",
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
    learn_file = ws / "memory" / "learnings.md"
    if learn_file.is_file():
        tags = Counter(TAG_RE.findall(learn_file.read_text(encoding="utf-8", errors="replace")))
        recurring = [f"{t}({c}次)" for t, c in tags.most_common() if c >= 2]
        if recurring:
            findings.append(
                Finding(
                    "WARN",
                    "evolution",
                    f"learnings.md 中有复发纠偏待晋升：{', '.join(recurring)}",
                    "周末在 Claude Code 中运行 `/promote` 生成脚本/Hook 晋升 Diff，落地后删除旧文字规则",
                )
            )
        else:
            findings.append(Finding("PASS", "evolution", "learnings.md 无积压的重复未晋升纠偏"))

    # Compute 0-100 score
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
