"""Command-line interface for PAOS v0.2 (Cross-Harness Control Plane & Safety Gate)."""

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
from .harnesses import (
    adopt_skills,
    clean_harnesses,
    resolve_targets,
    restore_links,
    scan_agy_plugins,
    scan_matrix,
    set_agy_plugins_state,
    use_profile,
)
from .skills import (
    apply_profile,
    clean_broken_skills,
    enable_skills,
    list_skills,
    park_skills,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _fmt_bytes(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.1f} MB"


def cmd_matrix(args: argparse.Namespace) -> int:
    rep = scan_matrix()
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0

    prof = rep["active_profile"] or "(未统一托管 — 运行 `paos use <profile>` 激活)"
    print(f"=== PAOS Cross-Harness 全景矩阵账单 (v{__version__}) ===")
    print(
        f"当前场景档位: {prof} | 已发现独立技能总数: {rep['unique_known_skills']} 个 | 真源仓({rep['store_dir']}): {rep['store_skill_count']} 个\n"
    )
    header = f"  {'客户端 (Harness)':<18} {'目录':<34} {'启用':>5} {'停放':>5} {'断链':>5} {'二级链':>6} {'预估启动税':>12}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for h in rep["harnesses"]:
        if not h["installed"]:
            print(f"  {h['label']:<18} {h['skills_dir']:<34} {'(未安装)':>29}")
            continue
        tok_str = f"~{h['estimated_tokens']:,} tok"
        print(
            f"  {h['label']:<18} {h['skills_dir']:<34} {h['active_count']:>5} {h['parked_count']:>5} "
            f"{h['broken_count']:>5} {h['daisy_chain_count']:>6} {tok_str:>12}"
        )

    t = rep["totals"]
    print("  " + "-" * (len(header) - 2))
    print(
        f"  跨端技能目录启动税: ~{t['estimated_tokens_across_harnesses']:,} Token | "
        f"Antigravity 插件包税: ~{t.get('estimated_agy_plugin_tokens', 0):,} Token | "
        f"失效软链: {t['broken_symlinks']} 个"
    )

    agp = rep.get("agy_plugins")
    if agp and agp["total_count"] > 0:
        heavy = [p for p in agp["plugins"] if p["enabled"] and p["estimated_tokens"] >= 1000]
        if heavy:
            h_desc = ", ".join(f"{p['name']}(~{p['estimated_tokens']:,} tok)" for p in heavy)
            print(f"  [!] Antigravity 常驻重型插件 ({agp['enabled_count']}/{agp['total_count']} 启用): {h_desc}")
            print("      -> 可运行 `paos plugins list` 或 `paos plugins disable <name>` 按需瘦身")

    # Actionable highlights
    for h in rep["harnesses"]:
        if h["broken_names"]:
            rec_note = (
                f"（其中 {len(h['recoverable_broken_names'])} 个存在完好真源，可自动治愈！）"
                if h["recoverable_broken_names"]
                else ""
            )
            sample = ", ".join(h["broken_names"][:5])
            more = f" 等 {len(h['broken_names'])} 个" if len(h["broken_names"]) > 5 else ""
            print(f"  [!] {h['label']} 存在失效软链: {sample}{more} {rec_note}")

    if rep["duplicates"]:
        div_cnt = t["diverged_physical_skills"]
        print(
            f"  [!] 跨端重复实体目录: {len(rep['duplicates'])} 个技能存有多份拷贝（其中 {div_cnt} 个内容已发生分叉漂移）"
        )

    if t["orphan_temp_files"] > 0:
        print(
            f"  [!] 客户端崩溃残留垃圾文件: {t['orphan_temp_files']} 个 ({_fmt_bytes(t['orphan_temp_bytes'])}) — 可运行 `paos clean` 安全清理"
        )

    if t["broken_symlinks"] > 0 or t["daisy_chain_symlinks"] > 0 or rep["duplicates"]:
        print("\n  -> 建议执行: `paos adopt --dry-run` 预览一级真源收归与断链自动治愈，或 `paos use <profile> --dry-run` 预览多端同步切档。")
    return 0


def cmd_adopt(args: argparse.Namespace) -> int:
    targets = resolve_targets(args.targets, Path.home()) if args.targets else None
    res = adopt_skills(targets=targets, dry_run=args.dry_run)
    mode = "(预览 --dry-run，未改动磁盘)" if args.dry_run else "(已完成收归，支持 `paos restore-links` 回滚)"
    print(f"=== PAOS Adopt 一级物理真源收归 {mode} ===")
    print(f"  目标客户端      : {', '.join(res['targets'])}")
    print(f"  物理真源目录    : {res['store_dir']}")
    print(f"  收归/索引技能数 : {res['adopted_count']} 个")
    print(f"  自动治愈断链数  : {len(res['healed_broken_links'])} 个")
    if res["backed_up_diverged"]:
        print(f"  分叉副本安全备份: {', '.join(res['backed_up_diverged'])} -> ~/.paos/backups/")
    if res["snapshot_path"]:
        print(f"  拓扑回滚快照    : {res['snapshot_path']}")
    if args.dry_run and res["actions"]:
        print("\n  变更预览 (前 20 条):")
        for act in res["actions"][:20]:
            print(f"    * {act}")
        if len(res["actions"]) > 20:
            print(f"    ... 其余 {len(res['actions']) - 20} 条已省略")
    return 0


def cmd_restore_links(_args: argparse.Namespace) -> int:
    ok, msg = restore_links()
    print(msg)
    return 0 if ok else 1


def cmd_use(args: argparse.Namespace) -> int:
    pf = Path(args.file) if args.file else (_repo_root() / "config" / "skill-profiles.json")
    if not args.profile:
        cfg = json.loads(pf.read_text(encoding="utf-8"))
        print("=== PAOS 跨端技能预设档位 (`paos use <profile>`) ===")
        for k, v in (cfg.get("profiles") or {}).items():
            print(f"  * {k:<10} — {v.get('description', '')}")
        return 0

    targets = resolve_targets(args.targets, Path.home()) if args.targets else None
    res = use_profile(args.profile, pf, targets=targets, dry_run=args.dry_run)
    mode = "(--dry-run 预览，未落盘)" if args.dry_run else "(已同步生效，重开对应客户端会话起效)"
    print(f"=== PAOS Use 跨端切档: [{res['profile']}] {mode} ===")
    if res["description"]:
        print(f"  说明: {res['description']}")
    print(f"  匹配启用技能池 ({res['desired_skill_count']} 个): {', '.join(res['desired_skills']) or '无'}\n")

    for h in res["harnesses"]:
        delta = h["delta_tokens"]
        sign = "+" if delta > 0 else ""
        print(
            f"  [{h['label']:<14}] 启用 {h['before_active']:>2} -> {h['after_active']:>2} 个 | "
            f"启动税 ~{h['before_tokens']:,} -> ~{h['after_tokens']:,} tok ({sign}{delta:,} tok) | "
            f"停放 -{h['parked_count']} / 挂载 +{h['enabled_count']}"
        )
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    targets = resolve_targets(args.targets, Path.home()) if args.targets else None
    res = clean_harnesses(targets=targets, heal_links=not args.no_heal, dry_run=args.dry_run)
    mode = "(--dry-run 预览，未删除文件)" if args.dry_run else "(清理完成)"
    print(f"=== PAOS Clean 跨客户端状态与断链治理 {mode} ===")
    print(
        f"  孤儿临时文件清理: {len(res['removed_orphan_files'])} 个 (释放 {_fmt_bytes(res['reclaimed_bytes'])})"
    )
    for f in res["removed_orphan_files"][:12]:
        print(f"    - ~/{f}")
    if len(res["removed_orphan_files"]) > 12:
        print(f"    ... 其余 {len(res['removed_orphan_files']) - 12} 个文件")

    print(f"  二级断链自动治愈: {len(res['healed_symlinks'])} 个")
    for s in res["healed_symlinks"][:15]:
        print(f"    + {s}")
    if len(res["healed_symlinks"]) > 15:
        print(f"    ... 其余 {len(res['healed_symlinks']) - 15} 个链接")

    print(f"  无源死链移入隔离: {len(res['quarantined_broken_symlinks'])} 个 (移至各端 skills-off/_broken/)")
    for q in res["quarantined_broken_symlinks"]:
        print(f"    ~ {q}")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    sub = args.plugins_cmd
    if sub == "list":
        info = scan_agy_plugins()
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
            return 0
        print(
            f"=== Antigravity 插件包启动税账单 ({info['enabled_count']}/{info['total_count']} 启用, 累计 ~{info['enabled_tokens']:,} Token) ==="
        )
        for p in info["plugins"]:
            st = "ENABLED " if p["enabled"] else "disabled"
            mcp_tag = " + MCP" if p["has_mcp"] else ""
            print(
                f"  [{st}] {p['name']:<26} | {p['skill_count']:>2} skills, {p['rule_count']} rules{mcp_tag:<6} | ~{p['estimated_tokens']:,} tok"
            )
        return 0

    enable_flag = sub == "enable"
    res = set_agy_plugins_state(args.names, enabled=enable_flag, dry_run=args.dry_run)
    action = "启用" if enable_flag else "停用"
    mode = "(--dry-run 预览)" if args.dry_run else "(已写入配置，新开会话生效)"
    sign = "+" if res["delta_tokens"] > 0 else ""
    print(
        f"=== Antigravity 插件{action} {mode}: {', '.join(res['changed']) or '无变更'} (启动税变化 {sign}{res['delta_tokens']:,} tok) ==="
    )
    if res["missing"]:
        print(f"  未找到插件: {', '.join(res['missing'])}", file=sys.stderr)
    return 0 if not res["missing"] else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve() if args.workspace else Path.cwd()
    report = run_doctor(workspace=ws)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if report["summary"]["fail"] > 0 else 0

    print(f"=== PAOS Doctor 体检报告 (健康分: {report['score']}/100) ===")
    print(f"工作区: {report['workspace']}")
    sk = report["skills"]
    print(
        f"常驻用户 Skill: {sk['active']} 个 (预估 ~{sk['estimated_tokens']} Token) | "
        f"skills-off 坟场: {sk['parked']} 个\n"
    )

    icons = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]"}
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
    include_codex = bool(args.all or args.codex)
    res = apply_harden(
        repo_dir=repo,
        dry_run=args.dry_run,
        configure_git=not args.no_git,
        include_codex=include_codex,
    )
    if args.dry_run:
        print("=== PAOS Harden 预览 (--dry-run，未写入磁盘) ===")
        print("[Claude Code ~/.claude/settings.json]")
        print(res["diff"] or "  已包含全部安全项，无需改动。")
        if res["codex"]:
            print("\n[Codex ~/.codex/rules/paos-guardrails.rules]")
            print(res["codex"]["diff"] or "  已包含全部 Starlark 拦截规则，无需改动。")
            for line in res["codex"]["verify_details"]:
                print(f"  {line}")
        return 0

    print("=== PAOS Harden 安全加固完成 ===")
    print(f"  [Claude] 已部署钩子 ({len(res['deployed_hooks'])} 个): ~/.claude/hooks/")
    if res["backup_path"]:
        print(f"  [Claude] 原配置已备份: {res['backup_path']}")
    print(
        f"  [Claude] 已更新安全配置: {res['settings_path']}"
        if res["changed"]
        else f"  [Claude] 配置已是最新: {res['settings_path']}"
    )
    if res["global_gitignore"]:
        print(f"  [Git]    已锁定全局 gitignore: {res['global_gitignore']}")
    elif res.get("global_gitignore_warning"):
        print(
            f"  [提示] 全局 gitignore 受沙盒限制未写入 ({res['global_gitignore_warning']})，可在宿主机手动执行 git config --global core.excludesfile ~/.gitignore_global"
        )

    if res["codex"]:
        cx = res["codex"]
        if cx["backup_path"]:
            print(f"  [Codex]  原规则已备份: {cx['backup_path']}")
        print(
            f"  [Codex]  已写入 Starlark 门禁: {cx['rules_path']}"
            if cx["changed"]
            else f"  [Codex]  规则已是最新: {cx['rules_path']}"
        )
        for line in cx["verify_details"]:
            print(f"           {line}")
        if not cx["verified"]:
            return 1
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
        today_items = [
            l.strip() for l in today_f.read_text(encoding="utf-8").splitlines() if re.match(r"^\s*-\s*\[", l)
        ]

    inbox_cnt = 0
    if inbox_f.is_file():
        inbox_cnt = sum(1 for l in inbox_f.read_text(encoding="utf-8").splitlines() if re.match(r"^\s*-\s+\S", l))

    mem_lines = len(index_f.read_text(encoding="utf-8").splitlines()) if index_f.is_file() else 0
    doc = run_doctor(workspace=ws)
    mat = scan_matrix()

    print(f"=== PAOS 个人操作系统仪表盘 ({datetime.now().strftime('%Y-%m-%d')}) ===")
    print(f"安全健康分 : {doc['score']}/100 ({doc['summary']['fail']} 阻断 / {doc['summary']['warn']} 警告)")
    print(
        f"五端累计税 : ~{mat['totals']['estimated_tokens_across_harnesses']:,} Token | "
        f"断链: {mat['totals']['broken_symlinks']} | 当前档位: {mat['active_profile'] or '未统一托管'}"
    )
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
        description="PAOS v0.2 — 跨客户端统一技能切档 (`nvm`)、物理真源防断链 (`chezmoi`) 与安全控制面 CLI",
    )
    p.add_argument("--version", action="version", version=f"paos {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # v0.2 Cross-Harness Commands
    p_mat = sub.add_parser(
        "matrix", help="1 秒扫描 Claude / Codex / .agents / Antigravity / Cursor 五端技能税与连环断链"
    )
    p_mat.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_mat.set_defaults(func=cmd_matrix)

    p_use = sub.add_parser(
        "use", help="Agent 圈的 `nvm use`：0.1 秒跨多客户端同步切换常驻技能档位 (minimal/writing/coding/video/lark/all)"
    )
    p_use.add_argument("profile", nargs="?", help="预设档位名称，留空则列出全部档位")
    p_use.add_argument("--targets", help="逗号分隔的目标客户端（默认全部已安装端：claude,codex,agents,antigravity,cursor）")
    p_use.add_argument("--file", help="自定义 skill-profiles.json 路径")
    p_use.add_argument("--dry-run", action="store_true", help="仅预览各端 Token 税变化，不落盘")
    p_use.set_defaults(func=cmd_use)

    p_adp = sub.add_parser(
        "adopt", help="将多端分散技能收归 ~/.paos/store/ 一级真源并自动治愈二级连环断链"
    )
    p_adp.add_argument("--targets", help="逗号分隔的目标客户端（默认全部已安装端）")
    p_adp.add_argument("--dry-run", action="store_true", help="仅预览收归与治愈动作，不改磁盘")
    p_adp.set_defaults(func=cmd_adopt)

    p_rst = sub.add_parser("restore-links", help="从 ~/.paos/snapshots/ 快照一键回滚 paos adopt 前的软链拓扑")
    p_rst.set_defaults(func=cmd_restore_links)

    p_cln = sub.add_parser("clean", help="安全清理多客户端孤儿 .tmp-* 崩溃残留文件，并自动治愈/隔离失效软链")
    p_cln.add_argument("--targets", help="逗号分隔的目标客户端（默认全部已安装端）")
    p_cln.add_argument("--no-heal", action="store_true", help="仅隔离失效软链，不尝试从真源自动修复")
    p_cln.add_argument("--dry-run", action="store_true", help="仅预览待清理文件与修复项，不落盘")
    p_cln.set_defaults(func=cmd_clean)

    p_plg = sub.add_parser("plugins", help="查看与按需启停 Antigravity (`~/.gemini/config/plugins/`) 插件包税")
    plg_sub = p_plg.add_subparsers(dest="plugins_cmd", required=True)
    p_plg_ls = plg_sub.add_parser("list", help="列出各插件包含的 Skill/Rule/MCP 数量与预估启动 Token 税")
    p_plg_ls.add_argument("--json", action="store_true")
    p_plg_dis = plg_sub.add_parser("disable", help="按需停用低频领域插件（如 genomics chemistry firebase），保留安装不删除")
    p_plg_dis.add_argument("names", nargs="+", help="插件目录名")
    p_plg_dis.add_argument("--dry-run", action="store_true")
    p_plg_en = plg_sub.add_parser("enable", help="随时重新启用指定插件")
    p_plg_en.add_argument("names", nargs="+", help="插件目录名")
    p_plg_en.add_argument("--dry-run", action="store_true")
    p_plg.set_defaults(func=cmd_plugins)

    # Core v0.1 Commands (100% preserved & enhanced)
    p_doc = sub.add_parser("doctor", help="执行 5 维本机上下文膨胀与安全护栏真机体检")
    p_doc.add_argument("--workspace", help="指定工作区目录（默认当前目录）")
    p_doc.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_doc.set_defaults(func=cmd_doctor)

    p_har = sub.add_parser("harden", help="非破坏性加固 Claude Code 沙盒/钩子，可选同步写入 Codex Starlark 门禁")
    p_har.add_argument("--all", action="store_true", help="同时加固 Claude Code 与 Codex CLI/App (`~/.codex/rules/`)")
    p_har.add_argument("--codex", action="store_true", help="包含 Codex Starlark execpolicy 规则生成与编译器校验")
    p_har.add_argument("--dry-run", action="store_true", help="仅打印 unified diff 预览，不修改任何文件")
    p_har.add_argument("--no-git", action="store_true", help="跳过全局 gitignore 配置")
    p_har.set_defaults(func=cmd_harden)

    p_rb = sub.add_parser("rollback", help="一键回滚最近一次 paos harden 修改前的 settings.json")
    p_rb.set_defaults(func=cmd_rollback)

    p_sk = sub.add_parser("skills", help="单端管理 ~/.claude/skills 与 skills-off/ 坟场")
    sk_sub = p_sk.add_subparsers(dest="skills_cmd", required=True)
    p_sk_ls = sk_sub.add_parser("list", help="列出启用与停放的 Skill 及预估 Token 开销")
    p_sk_ls.add_argument("--json", action="store_true")
    p_sk_park = sk_sub.add_parser("park", help="将低频 Skill 移入 ~/.claude/skills-off/ 释放上下文")
    p_sk_park.add_argument("names", nargs="+", help="要停放的 Skill 名称")
    p_sk_en = sk_sub.add_parser("enable", help="从 ~/.claude/skills-off/ 恢复启用指定 Skill")
    p_sk_en.add_argument("names", nargs="+", help="要恢复的 Skill 名称")
    sk_sub.add_parser("clean-broken", help="将失效软链接移入 skills-off/")
    p_sk_prof = sk_sub.add_parser("profile", help="按工作场景切换 Claude 单端常驻 Skill 集合")
    p_sk_prof.add_argument("name", nargs="?", help="预设名称（如 minimal / writing / coding），留空则列出全部")
    p_sk_prof.add_argument("--file", help="自定义 skill-profiles.json 路径")
    p_sk_prof.add_argument("--dry-run", action="store_true", help="仅预览变更")
    p_sk.set_defaults(func=cmd_skills)

    p_cap = sub.add_parser("capture", help="零 Token 毫秒级把灵感/链接追加进 memory/INBOX.md")
    p_cap.add_argument("text", nargs="+", help="要记录的文本或链接")
    p_cap.add_argument("--workspace", help="指定个人 OS 工作区路径")
    p_cap.set_defaults(func=cmd_capture)

    p_st = sub.add_parser("status", help="一屏查看今日 P0、五端累计税、收件箱与安全评分")
    p_st.add_argument("--workspace", help="指定个人 OS 工作区路径")
    p_st.set_defaults(func=cmd_status)

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
