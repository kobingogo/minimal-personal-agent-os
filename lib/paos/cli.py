"""Command-line interface for PAOS (`paos`)."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys
from typing import List

from . import __version__
from .doctor import run_doctor
from .harden import apply_harden, rollback_settings
from .skills import (
    apply_profile,
    clean_broken_skills,
    enable_skills,
    list_skills,
    park_skills,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def cmd_doctor(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve() if args.workspace else Path.cwd()
    report = run_doctor(workspace=ws)
    if args.json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 1 if report["summary"]["fail"] > 0 else 0

    icons = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]"}
    print(f"=== PAOS Doctor 体检报告 (健康分: {report['score']}/100) ===")
    print(f"工作区: {report['workspace']}")
    print(
        f"常驻用户 Skill: {report['skills']['active']} 个 "
        f"(预估 ~{report['skills']['estimated_tokens']} Token) | "
        f"skills-off 坟场: {report['skills']['parked']} 个\n"
    )
    for f in report["findings"]:
        tag = icons.get(f["level"], f"[{f['level']}]")
        print(f"  {tag} ({f['dimension']}) {f['message']}")
        if f["fix"] and f["level"] != "PASS":
            print(f"         -> 建议修复: {f['fix']}")

    s = report["summary"]
    print(f"\n汇总: {s['pass']} 通过 | {s['warn']} 警告 | {s['fail']} 阻断风险")
    return 1 if s["fail"] > 0 else 0


def cmd_harden(args: argparse.Namespace) -> int:
    repo = _repo_root()
    res = apply_harden(repo_dir=repo, dry_run=args.dry_run, configure_git=not args.no_git)
    if args.dry_run:
        print("=== PAOS Harden 预览 (--dry-run，未写入磁盘) ===")
        print(res["diff"] or "  ~/.claude/settings.json 已包含全部安全项，无需改动。")
        return 0

    print("=== PAOS Harden 安全加固完成 ===")
    print(f"  已部署钩子 ({len(res['deployed_hooks'])} 个): ~/.claude/hooks/")
    if res["backup_path"]:
        print(f"  原配置已备份: {res['backup_path']}")
    print(f"  已更新安全配置: {res['settings_path']}" if res["changed"] else f"  配置已是最新: {res['settings_path']}")
    if res["global_gitignore"]:
        print(f"  已锁定全局 gitignore: {res['global_gitignore']}")
    elif res.get("global_gitignore_warning"):
        print(f"  [提示] 全局 gitignore 受沙盒限制未写入 ({res['global_gitignore_warning']})，可在宿主机手动执行 git config --global core.excludesfile ~/.gitignore_global")
    return 0


def cmd_rollback(_args: argparse.Namespace) -> int:
    ok, msg = rollback_settings()
    print(msg)
    return 0 if ok else 1


def cmd_skills(args: argparse.Namespace) -> int:
    sub = args.skills_cmd
    if sub == "list":
        info = list_skills()
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
            return 0
        print(
            f"=== 常驻启用 Skill ({info['active_count']} 个, 预估启动占用 ~{info['estimated_active_tokens']} Token) ==="
        )
        for s in info["active"]:
            status = " [BROKEN SYMLINK]" if s["broken"] else f" (~{s['est_discovery_tokens']} tok)"
            print(f"  + {s['name']}{status}")
        print(f"\n=== 技能坟场 skills-off ({info['parked_count']} 个，零上下文占用) ===")
        for s in info["parked"][:25]:
            print(f"  - {s['name']}")
        if info["parked_count"] > 25:
            print(f"  ... 其余 {info['parked_count'] - 25} 个已隐藏")
        return 0

    if sub == "park":
        moved, missing = park_skills(args.names)
        if moved:
            print(f"已移入 ~/.claude/skills-off/ ({len(moved)} 个): {', '.join(moved)}")
            print("提示：请新开 Claude Code 会话使 /context 瘦身生效。")
        if missing:
            print(f"未在启用目录找到: {', '.join(missing)}", file=sys.stderr)
        return 0 if moved else 1

    if sub == "enable":
        restored, missing = enable_skills(args.names)
        if restored:
            print(f"已恢复启用 ({len(restored)} 个): {', '.join(restored)}")
            print("提示：请新开 Claude Code 会话加载恢复的 Skill。")
        if missing:
            print(f"未在 skills-off/ 找到: {', '.join(missing)}", file=sys.stderr)
        return 0 if restored else 1

    if sub == "clean-broken":
        cleaned = clean_broken_skills()
        if cleaned:
            print(f"已清理 {len(cleaned)} 个失效软链接至 skills-off/: {', '.join(cleaned)}")
        else:
            print("未发现失效软链接。")
        return 0

    if sub == "profile":
        pf = Path(args.file) if args.file else (_repo_root() / "config" / "skill-profiles.json")
        if not args.name:
            cfg = json.loads(pf.read_text(encoding="utf-8"))
            print("=== 可用技能场景预设 (Skill Profiles) ===")
            for k, v in (cfg.get("profiles") or {}).items():
                print(f"  * {k:10s} — {v.get('description', '')}")
            return 0
        res = apply_profile(args.name, pf, dry_run=args.dry_run)
        mode = "(预览 --dry-run)" if args.dry_run else "(已生效，新会话起效)"
        print(f"=== 切换技能预设: {res['profile']} {mode} ===")
        print(f"  移入 skills-off ({len(res['to_park'])}): {', '.join(res['to_park']) or '无'}")
        print(f"  恢复启用        ({len(res['to_enable'])}): {', '.join(res['to_enable']) or '无'}")
        print(f"  最终常驻启用    ({len(res['resulting_active'])}): {', '.join(res['resulting_active']) or '无'}")
        return 0

    return 1


def cmd_capture(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve() if args.workspace else _repo_root()
    inbox = ws / "memory" / "INBOX.md"
    inbox.parent.mkdir(parents=True, exist_ok=True)
    text = " ".join(args.text).strip()
    if not text:
        print("错误：请输入要记录的内容。", file=sys.stderr)
        return 1
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    line = f"- [{ts}] {text}\n"
    with inbox.open("a", encoding="utf-8") as f:
        f.write(line)
    print(f"已记入收件箱 ({inbox}): {line.strip()}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve() if args.workspace else _repo_root()
    mem = ws / "memory"
    today_f = mem / "TODAY.md"
    inbox_f = mem / "INBOX.md"
    index_f = mem / "MEMORY.md"

    today_items = []
    if today_f.is_file():
        today_items = [l.strip() for l in today_f.read_text(encoding="utf-8").splitlines() if re.match(r"^\s*-\s*\[", l)]

    inbox_cnt = 0
    if inbox_f.is_file():
        inbox_cnt = sum(1 for l in inbox_f.read_text(encoding="utf-8").splitlines() if re.match(r"^\s*-\s+\S", l))

    mem_lines = len(index_f.read_text(encoding="utf-8").splitlines()) if index_f.is_file() else 0
    doc = run_doctor(workspace=ws)

    print(f"=== PAOS 个人操作系统仪表盘 ({datetime.now().strftime('%Y-%m-%d')}) ===")
    print(f"安全健康分 : {doc['score']}/100 ({doc['summary']['fail']} 阻断 / {doc['summary']['warn']} 警告)")
    print(f"常驻 Skill : {doc['skills']['active']} 启用 (~{doc['skills']['estimated_tokens']} Token) | {doc['skills']['parked']} 停放在 skills-off/")
    print(f"记忆总索引 : {mem_lines}/200 行预算")
    print(f"待分诊碎片 : {inbox_cnt} 条 (memory/INBOX.md)")
    print("今日 P0    :")
    if today_items:
        for item in today_items[:5]:
            print(f"  {item}")
    else:
        print("  (空 — 在 Claude Code 中敲 /triage 生成今日聚焦)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="paos",
        description="PAOS — 零外部依赖的三层确定性个人 AI 操作系统控制面 CLI",
    )
    p.add_argument("--version", action="version", version=f"paos {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_doc = sub.add_parser("doctor", help="执行 5 维本机上下文膨胀与安全护栏真机体检")
    p_doc.add_argument("--workspace", help="指定工作区目录（默认当前目录）")
    p_doc.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_doc.set_defaults(func=cmd_doctor)

    p_har = sub.add_parser("harden", help="非破坏性合并 ~/.claude/settings.json 沙盒、权限锁与防呆钩子")
    p_har.add_argument("--dry-run", action="store_true", help="仅打印 unified diff 预览，不修改任何文件")
    p_har.add_argument("--no-git", action="store_true", help="跳过全局 gitignore 配置")
    p_har.set_defaults(func=cmd_harden)

    p_rb = sub.add_parser("rollback", help="一键回滚最近一次 paos harden 修改前的 settings.json")
    p_rb.set_defaults(func=cmd_rollback)

    p_sk = sub.add_parser("skills", help="管理 ~/.claude/skills 与 skills-off/ 坟场及场景预设")
    sk_sub = p_sk.add_subparsers(dest="skills_cmd", required=True)

    p_sk_ls = sk_sub.add_parser("list", help="列出启用与停放的 Skill 及预估 Token 开销")
    p_sk_ls.add_argument("--json", action="store_true")

    p_sk_park = sk_sub.add_parser("park", help="将低频 Skill 移入 ~/.claude/skills-off/ 释放上下文")
    p_sk_park.add_argument("names", nargs="+", help="要停放的 Skill 名称")

    p_sk_en = sk_sub.add_parser("enable", help="从 ~/.claude/skills-off/ 恢复启用指定 Skill")
    p_sk_en.add_argument("names", nargs="+", help="要恢复的 Skill 名称")

    sk_sub.add_parser("clean-broken", help="将失效软链接移入 skills-off/")

    p_sk_prof = sk_sub.add_parser("profile", help="按工作场景一键切换常驻 Skill 集合")
    p_sk_prof.add_argument("name", nargs="?", help="预设名称（如 minimal / writing / coding），留空则列出全部")
    p_sk_prof.add_argument("--file", help="自定义 skill-profiles.json 路径")
    p_sk_prof.add_argument("--dry-run", action="store_true", help="仅预览变更")
    p_sk.set_defaults(func=cmd_skills)

    p_cap = sub.add_parser("capture", help="零 Token 毫秒级把灵感/链接追加进 memory/INBOX.md")
    p_cap.add_argument("text", nargs="+", help="要记录的文本或链接")
    p_cap.add_argument("--workspace", help="指定个人 OS 工作区路径")
    p_cap.set_defaults(func=cmd_capture)

    p_st = sub.add_parser("status", help="一屏查看今日 P0、收件箱、记忆水位与安全评分")
    p_st.add_argument("--workspace", help="指定个人 OS 工作区路径")
    p_st.set_defaults(func=cmd_status)

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
