"""Command-line interface for PAOS v0.1.0 (Personal Agent OS Kernel & Cross-Harness Control Plane)."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys
from typing import List

from . import __version__
from .audit import read_audit_events
from .cron import execute_cron_job_now, install_cron_job, list_cron_jobs, remove_cron_job
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
from .notify import send_notification
from .scheduler import run_cold_review, run_task
from .skills import (
    apply_profile,
    clean_broken_skills,
    enable_skills,
    list_skills,
    park_skills,
)
from .sync_bus import brain_root, init_brain, promote_learnings, sync_brain


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

    t = rep["totals"]
    print("=== PAOS Matrix 跨客户端技能与状态全景报告 ===")
    print(
        f"当前激活档位: {rep['active_profile'] or '未统一托管 (运行 `paos use <profile>` 切换)'} | "
        f"真源仓: {rep['store_skill_count']} 个 ({rep['store_dir']})"
    )
    print(
        f"五端累计启动税: ~{t['estimated_tokens_across_harnesses']:,} Token "
        f"(启用槽位合计 {t['active_entries_across_harnesses']} 项 | 唯一技能 {rep['unique_known_skills']} 个)\n"
    )
    print(f"  {'客户端 (Harness)':<30} {'启用':>5} {'停放':>5} {'断链':>5} {'二级链':>6} {'预估启动税':>14}")
    print("  " + "-" * 72)
    for h in rep["harnesses"]:
        if not h["installed"]:
            continue
        print(
            f"  {h['label']:<30} {h['active_count']:>5} {h['parked_count']:>5} "
            f"{h['broken_count']:>5} {h['daisy_chain_count']:>6} "
            f"{'~' + format(h['estimated_tokens'], ',') + ' tok':>14}"
        )

    agy = rep["agy_plugins"]
    if agy["total_count"] > 0:
        print(
            f"  {'Antigravity Plugins (config)':<30} "
            f"{agy['enabled_count']:>5} {agy['disabled_count']:>5} {'0':>5} {'0':>6} "
            f"{'~' + format(agy['enabled_tokens'], ',') + ' tok':>14}"
        )

    print("\n--- 跨端拓扑隐患诊断 ---")
    if t["broken_symlinks"] > 0:
        print(f"  [WARN] 发现 {t['broken_symlinks']} 个失效软链接 -> 运行 `paos clean` 或 `paos adopt` 自动治愈/隔离")
        for h in rep["harnesses"]:
            if h["broken_names"]:
                print(f"         * {h['id']}: {', '.join(h['broken_names'][:8])}")
    else:
        print("  [PASS] 五大客户端零失效软链接")

    if t["daisy_chain_symlinks"] > 0:
        print(
            f"  [WARN] 发现 {t['daisy_chain_symlinks']} 根跨客户端二级软链（如指向 .claude/skills，单端停用即引发连环断链）"
        )
        print("         -> 运行 `paos adopt` 收归一级真源 `~/.paos/store/skills/` 彻底根治")
    else:
        print("  [PASS] 零跨客户端脆弱二级软链")

    diverged_dups = [d for d in rep["duplicates"] if d["diverged"]]
    if diverged_dups:
        print(f"  [WARN] 发现 {len(diverged_dups)} 个同名但内容分叉的物理拷贝:")
        for d in diverged_dups[:6]:
            locs = ", ".join(d["copies"])
            print(f"         * {d['skill']} ({locs})")

    if t["orphan_temp_files"] > 0:
        print(
            f"  [WARN] 发现 {t['orphan_temp_files']} 个客户端崩溃残留临时文件 (占用 {_fmt_bytes(t['orphan_temp_bytes'])}) "
            "-> 运行 `paos clean` 一键清理"
        )
    return 0


def cmd_adopt(args: argparse.Namespace) -> int:
    targets = resolve_targets(args.targets, Path.home()) if args.targets else None
    res = adopt_skills(targets=targets, dry_run=args.dry_run)
    mode = "(--dry-run 预览，未修改文件)" if args.dry_run else "(已完成，快照可随时 `paos restore-links` 回滚)"
    print(f"=== PAOS Adopt 一级物理真源收归 {mode} ===")
    print(f"  真源目录        : {res['store_dir']}")
    print(f"  收归/索引技能   : {res['adopted_count']} 个")
    print(f"  自动治愈二级断链: {len(res['healed_broken_links'])} 个")
    if res["healed_broken_links"]:
        print(f"                    {', '.join(res['healed_broken_links'][:12])}")
    if res["backed_up_diverged"]:
        print(f"  分叉副本安全备份: {len(res['backed_up_diverged'])} 个 (已存至 ~/.paos/backups/)")
    if res["snapshot_path"]:
        print(f"  回滚拓扑快照    : {res['snapshot_path']}")
    if args.dry_run and res["actions"]:
        print("\n  变更动作预览 (前 20 条):")
        for act in res["actions"][:20]:
            print(f"    - {act}")
        if len(res["actions"]) > 20:
            print(f"    ... 共 {len(res['actions'])} 条动作")
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
    res = use_profile(
        args.profile,
        pf,
        targets=targets,
        include_plugins=bool(args.include_plugins),
        dry_run=args.dry_run,
    )
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
    if res.get("agy_plugins") is not None:
        ap = res["agy_plugins"]
        sign = "+" if ap["delta_tokens"] > 0 else ""
        print(
            f"  [AGY Plugins   ] 启用 +{len(ap['enabled'])} / 停用 -{len(ap['disabled'])} | "
            f"插件税变化 {sign}{ap['delta_tokens']:,} tok"
        )
    if res.get("skipped_permissions"):
        print(f"  [提示] 沙盒只读目录已安全跳过 ({len(res['skipped_permissions'])} 项)")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    targets = resolve_targets(args.targets, Path.home()) if args.targets else None
    res = clean_harnesses(
        targets=targets,
        heal_links=not args.no_heal,
        prune_claude_state=bool(args.prune_claude_state),
        dry_run=args.dry_run,
    )
    mode = "(--dry-run 预览，未删除文件)" if args.dry_run else "(清理完成)"
    print(f"=== PAOS Clean 跨客户端状态与断链治理 {mode} ===")
    print(
        f"  孤儿临时文件清理: {len(res['removed_orphan_files'])} 个 | 累计释放空间: {_fmt_bytes(res['reclaimed_bytes'])}"
    )
    for f in res["removed_orphan_files"][:12]:
        print(f"    - ~/{f}")
    if len(res["removed_orphan_files"]) > 12:
        print(f"    ... 其余 {len(res['removed_orphan_files']) - 12} 个文件")

    if args.prune_claude_state:
        pruned = res.get("pruned_claude_projects") or []
        print(f"  ~/.claude.json 失效项目缓存瘦身: 移除 {len(pruned)} 个已删除路径")
        if res.get("claude_state_backup"):
            print(f"    备份位置: {res['claude_state_backup']}")

    print(f"  二级断链自动治愈: {len(res['healed_symlinks'])} 个")
    for s in res["healed_symlinks"][:15]:
        print(f"    + {s}")
    if len(res["healed_symlinks"]) > 15:
        print(f"    ... 其余 {len(res['healed_symlinks']) - 15} 个链接")

    print(f"  无源死链移入隔离: {len(res['quarantined_broken_symlinks'])} 个 (移至各端 skills-off/_broken/)")
    for q in res["quarantined_broken_symlinks"]:
        print(f"    ~ {q}")
    if res.get("skipped_permissions"):
        print(f"  [提示] 受当前沙盒权限限制已安全跳过 {len(res['skipped_permissions'])} 项")
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


def cmd_rollback(args: argparse.Namespace) -> int:
    ok, msg = rollback_settings(include_codex=bool(args.all or args.codex))
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


def _resolve_memory_dir(explicit_workspace: str | None) -> Path:
    if explicit_workspace:
        return Path(explicit_workspace).resolve() / "memory"
    shared = brain_root() / "memory"
    if shared.is_dir():
        return shared
    return _repo_root() / "memory"


def cmd_init(args: argparse.Namespace) -> int:
    seed = Path(args.seed_workspace).resolve() if args.seed_workspace else _repo_root()
    res = init_brain(seed_workspace=seed)
    print(f"=== PAOS Init 跨端共享大脑已就绪 ({res['brain_dir']}) ===")
    if res["created_files"]:
        for f in res["created_files"]:
            print(f"  + 初始化: {f}")
    else:
        print("  所有共享记忆与规则文件均已存在，未覆盖任何现有内容。")
    print("  下一步：运行 `paos sync --dry-run` 预览向 Claude / Codex / Antigravity / Cursor 的非破坏性挂载。")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    targets = [t.strip() for t in args.targets.split(",") if t.strip()] if args.targets else None
    res = sync_brain(targets=targets, dry_run=args.dry_run, remove=args.remove)
    action = "移除托管块" if args.remove else "同步挂载"
    mode = "(--dry-run 预览，未修改文件)" if args.dry_run else "(已非破坏性写入，首次触碰文件已自动备份至 ~/.paos/backups/)"
    print(f"=== PAOS Sync 跨客户端记忆与核心契约{action} {mode} ===")
    print(f"  共享真源: {res['brain_dir']}")
    for item in res["files"]:
        status = "CHANGED" if item["changed"] else "UNCHANGED"
        print(f"  [{status:<9}] ({item['target']}) {item['path']}")
        if args.dry_run and item["diff"]:
            print(item["diff"])
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    if args.file:
        lpath = Path(args.file).resolve()
    elif (Path.cwd() / "memory" / "learnings.md").is_file():
        lpath = Path.cwd() / "memory" / "learnings.md"
    elif (brain_root() / "memory" / "learnings.md").is_file():
        lpath = brain_root() / "memory" / "learnings.md"
    else:
        lpath = _repo_root() / "memory" / "learnings.md"

    res = promote_learnings(lpath, threshold=args.threshold, mark_promoted=args.apply)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    print(f"=== PAOS Promote 踩坑复发晋升审计 ({res['path']}) ===")
    if not res["candidates"]:
        print(f"  [PASS] 未发现复发 >= {res['threshold']} 次的未晋升 `[tag:...]` 条目。")
        return 0

    for c in res["candidates"]:
        print(f"\n  * [tag:{c['tag']}] 复发 {c['count']} 次 -> 建议优先写进 pre_tool_gate.py / 单测守卫，其次写进 CORE_RULES.md:")
        for entry in c["entries"]:
            print(f"      {entry}")
    if args.apply:
        print(f"\n  已将上述 {res['marked_count']} 条记录打上 `[promoted:YYYY-MM-DD]` 归档标记。")
    else:
        print("\n  提示：落地脚本或规则后，运行 `paos promote --apply` 将上述条目归档消警。")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    prompt = " ".join(args.prompt).strip()
    res = run_task(
        prompt=prompt,
        engine=args.engine,
        use_worktree=args.worktree,
        sandbox_mode=args.sandbox,
        max_budget_usd=args.max_budget_usd,
        max_turns=args.max_turns,
        timeout_sec=args.timeout,
        model=args.model,
        notify_on_done=args.notify,
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("dry_run") else (0 if res["exit_code"] == 0 else res["exit_code"])

    if res["dry_run"]:
        print("=== PAOS Run 受控调度预览 (--dry-run) ===")
        print(f"  执行引擎 : {res['engine']} | Worktree 隔离: {res['use_worktree']} | 超时熔断: {res['timeout_sec']}s")
        print(f"  工作目录 : {res['workdir']}")
        print(f"  编译命令 : {' '.join(res['command'])}")
        return 0

    print(f"=== PAOS Run 执行完毕 [{res['status'].upper()}] (耗时 {res['duration_ms'] / 1000:.1f}s) ===")
    print(f"  引擎: {res['engine']} | 退出码: {res['exit_code']} | 脱敏日志: {res['log_path']}")
    if res.get("worktree_branch"):
        print(f"  隔离分支保留供审查: {res['worktree_branch']} ({res['workdir']})")
    elif res.get("worktree_pruned_clean"):
        print("  隔离 Worktree 无文件改动，已自动清理回收。")
    if res["stdout_tail"]:
        print("\n--- 输出摘要 ---")
        print(res["stdout_tail"])
    return 0 if res["exit_code"] == 0 else 1


def cmd_review(args: argparse.Namespace) -> int:
    res = run_cold_review(
        base_branch=args.base,
        engine=args.engine,
        xhigh=args.xhigh,
        timeout_sec=args.timeout,
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("dry_run") else int(res["exit_code"])

    if res.get("dry_run"):
        print("=== PAOS Review 零记忆冷启动盲审预览 (--dry-run) ===")
        print(f"  审查引擎 : {res['engine']} (xhigh={res['xhigh']}) | 待审 Diff: {res['diff_chars']} chars")
        print(f"  编译命令 : {' '.join(res['command'][:6])} ...")
        return 0

    if res["status"] == "skipped_empty_diff":
        print(f"=== PAOS Review: {res['summary']} ===")
        return 0

    status_labels = {
        "p0_blocked": "BLOCK_P0 (发现阻断级缺陷，退出码 2)",
        "timeout": "TIMEOUT (盲审超时终止，退出码 124)",
        "failed": f"FAILED (审查引擎异常或缺少明确 PASS 结论，退出码 {res['exit_code']})",
        "ok": "PASS (无 P0 阻断缺陷)",
    }
    verdict = status_labels.get(res["status"], res["status"].upper())
    print(f"=== PAOS Review 金鱼冷启动盲审结果: {verdict} ===")
    print(f"  审查引擎: {res['engine']} | 耗时: {res['duration_ms'] / 1000:.1f}s | 完整报告: {res['report_path']}\n")
    print(res["output"])
    return int(res["exit_code"])


def cmd_logs(args: argparse.Namespace) -> int:
    events = read_audit_events(
        limit=args.limit,
        blocks_only=args.blocks_only,
        event_filter=args.event,
    )
    if args.json:
        print(json.dumps(events, ensure_ascii=False, indent=2))
        return 0

    print(f"=== PAOS Logs 本地脱敏安全与调度审计流 (最近 {len(events)} 条) ===")
    if not events:
        print("  (暂无审计记录 — 当门禁拦截高危命令或运行 `paos run/review/cron/notify` 时自动落盘至 ~/.paos/logs/audit.jsonl)")
        return 0
    for ev in events:
        dur = f" ({ev['duration_ms']}ms)" if "duration_ms" in ev else ""
        print(f"  [{ev.get('ts', '')}] [{ev.get('status', '').upper():<10}] ({ev.get('event')}/{ev.get('harness')}){dur} {ev.get('summary', '')}")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    msg = " ".join(args.message).strip()
    res = send_notification(
        title=args.title,
        message=msg,
        channel=args.channel,
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["ok"] else 1
    mode = "(--dry-run 预览)" if args.dry_run else ""
    print(f"=== PAOS Notify 单向脱敏推送 {mode} ===")
    for r in res["results"]:
        st = "OK" if r["ok"] else "FAIL"
        print(f"  [{st:<4}] ({r['channel']}) {r['detail']}")
    return 0 if res["ok"] else 1


def cmd_cron(args: argparse.Namespace) -> int:
    sub = args.cron_cmd
    if sub == "list":
        jobs = list_cron_jobs()
        if args.json:
            print(json.dumps(jobs, ensure_ascii=False, indent=2))
            return 0
        weekday_names = ("周日", "周一", "周二", "周三", "周四", "周五", "周六")
        print("=== PAOS Cron 零守护进程原生定时任务列表 ===")
        for j in jobs:
            st = "INSTALLED" if j["installed"] else "not-set  "
            wd_idx = j["weekday"]
            wd = weekday_names[wd_idx] if isinstance(wd_idx, int) and 0 <= wd_idx <= 6 else "每日"
            print(
                f"  [{st}] {j['name']:<16} | {wd} {j['hour']:02d}:{j['minute']:02d} | {j['description']}"
            )
        return 0

    if sub == "install":
        paos_bin = _repo_root() / "bin" / "paos"
        res = install_cron_job(
            job_name=args.job,
            paos_bin=paos_bin,
            hour=args.hour,
            minute=args.minute,
            weekday=args.weekday,
            custom_cmd=args.cmd_str,
            dry_run=args.dry_run,
        )
        mode = "(--dry-run 预览)" if args.dry_run else "(已注册至系统原生调度器)"
        print(f"=== PAOS Cron Install [{res['job']}] {mode} -> {res['path']} ===")
        if args.dry_run:
            print(res["preview"])
        return 0

    if sub == "remove":
        res = remove_cron_job(job_name=args.job, dry_run=args.dry_run)
        print(
            f"=== PAOS Cron Remove [{res['job']}]: {'已卸载' if res['removed'] else '未安装'} ({res['path']}) ==="
        )
        return 0

    if sub == "run-now":
        res = execute_cron_job_now(
            job_name=args.job,
            repo_dir=_repo_root(),
            notify=not args.no_notify,
            dry_run=args.dry_run,
        )
        if args.dry_run:
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        print(f"=== PAOS Cron Run [{res['job']}] -> {res['status'].upper()} ===")
        print(res.get("summary", ""))
        return 0 if res["status"] in ("ok", "skipped_locked") else 1

    return 1


def cmd_capture(args: argparse.Namespace) -> int:
    mem = _resolve_memory_dir(args.workspace)
    inbox = mem / "INBOX.md"
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
    mem = _resolve_memory_dir(args.workspace)
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
    cron_installed = sum(1 for j in list_cron_jobs() if j["installed"])
    recent_blocks = len(read_audit_events(limit=50, blocks_only=True))
    brain_ready = "已挂载 ~/.paos/brain" if brain_root().is_dir() else "工作区本地模式 (`paos init` 开启跨端共享)"

    print(f"=== PAOS v{__version__} 个人操作系统仪表盘 ({datetime.now().strftime('%Y-%m-%d')}) ===")
    print(f"安全健康分 : {doc['score']}/100 ({doc['summary']['fail']} 阻断 / {doc['summary']['warn']} 警告 | 近 50 条拦截告警: {recent_blocks} 次)")
    print(
        f"五端累计税 : ~{mat['totals']['estimated_tokens_across_harnesses']:,} Token | "
        f"断链: {mat['totals']['broken_symlinks']} | 当前档位: {mat['active_profile'] or '未统一托管'}"
    )
    print(f"记忆与巡检 : {brain_ready} | 索引 {mem_lines}/200 行 | 原生定时任务: {cron_installed} 个启用")
    print(f"待分诊碎片 : {inbox_cnt} 条 ({inbox_f})")
    print("今日 P0    :")
    if today_items:
        for item in today_items[:5]:
            print(f"  {item}")
    else:
        print("  (空 — 编辑 TODAY.md 或运行 /triage 生成今日聚焦)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="paos",
        description="PAOS v0.1.0 — 零依赖个人 AI Agent 操作系统内核（跨端切档、记忆同步、门禁审计、隔离调度与原生巡检）",
    )
    p.add_argument("--version", action="version", version=f"paos {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Subsystem 1: Cross-Harness Package & Plugin Manager
    p_mat = sub.add_parser(
        "matrix", help="1 秒扫描 Claude / Codex / .agents / Antigravity / Cursor 五端技能税与连环断链"
    )
    p_mat.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_mat.set_defaults(func=cmd_matrix)

    p_use = sub.add_parser(
        "use", help="Agent 圈的 `nvm use`：0.1 秒跨多客户端同步切换常驻技能与插件档位"
    )
    p_use.add_argument("profile", nargs="?", help="预设档位名称，留空则列出全部档位")
    p_use.add_argument("--targets", help="逗号分隔的目标客户端（默认全部已安装端：claude,codex,agents,antigravity,cursor）")
    p_use.add_argument("-p", "--include-plugins", action="store_true", help="同步按档位切换 Antigravity 插件包开关")
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

    p_cln = sub.add_parser("clean", help="安全清理多客户端孤儿 .tmp-* 残留、失效软链及陈旧 .claude.json 项目缓存")
    p_cln.add_argument("--targets", help="逗号分隔的目标客户端（默认全部已安装端）")
    p_cln.add_argument("--no-heal", action="store_true", help="仅隔离失效软链，不尝试从真源自动修复")
    p_cln.add_argument("--prune-claude-state", action="store_true", help="自动备份并清理 ~/.claude.json 中已删除路径的历史项目缓存")
    p_cln.add_argument("--dry-run", action="store_true", help="仅预览待清理文件与修复项，不落盘")
    p_cln.set_defaults(func=cmd_clean)

    p_plg = sub.add_parser("plugins", help="查看与按需启停 Antigravity (`~/.gemini/config/plugins/`) 插件包税")
    plg_sub = p_plg.add_subparsers(dest="plugins_cmd", required=True)
    p_plg_ls = plg_sub.add_parser("list", help="列出各插件包含的 Skill/Rule/MCP 数量与预估启动 Token 税")
    p_plg_ls.add_argument("--json", action="store_true")
    p_plg_dis = plg_sub.add_parser("disable", help="按需停用低频领域插件，保留安装不删除")
    p_plg_dis.add_argument("names", nargs="+", help="插件目录名")
    p_plg_dis.add_argument("--dry-run", action="store_true")
    p_plg_en = plg_sub.add_parser("enable", help="随时重新启用指定插件")
    p_plg_en.add_argument("names", nargs="+", help="插件目录名")
    p_plg_en.add_argument("--dry-run", action="store_true")
    p_plg.set_defaults(func=cmd_plugins)

    # Subsystem 2: Security Gate, Doctor & Audit Logs
    p_doc = sub.add_parser("doctor", help="执行跨客户端上下文膨胀、沙盒门禁与明文密钥风险体检")
    p_doc.add_argument("--workspace", help="指定工作区目录（默认当前目录）")
    p_doc.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_doc.set_defaults(func=cmd_doctor)

    p_har = sub.add_parser("harden", help="非破坏性加固 Claude Code 沙盒/钩子与 Codex Starlark 门禁")
    p_har.add_argument("--all", action="store_true", help="同时加固 Claude Code 与 Codex CLI/App (`~/.codex/rules/`)")
    p_har.add_argument("--codex", action="store_true", help="包含 Codex Starlark execpolicy 规则生成与编译器校验")
    p_har.add_argument("--dry-run", action="store_true", help="仅打印 unified diff 预览，不修改任何文件")
    p_har.add_argument("--no-git", action="store_true", help="跳过全局 gitignore 配置")
    p_har.set_defaults(func=cmd_harden)

    p_rb = sub.add_parser("rollback", help="一键回滚最近一次 paos harden 修改前的配置备份")
    p_rb.add_argument("--all", action="store_true", help="同时回滚 Claude settings.json 与 Codex paos-guardrails.rules")
    p_rb.add_argument("--codex", action="store_true", help="包含 Codex 门禁规则回滚")
    p_rb.set_defaults(func=cmd_rollback)

    p_logs = sub.add_parser("logs", help="查看本地脱敏门禁拦截、熔断与任务调度审计日志 (`~/.paos/logs/audit.jsonl`)")
    p_logs.add_argument("--limit", type=int, default=30, help="显示最近 N 条记录（默认 30）")
    p_logs.add_argument("--blocks-only", action="store_true", help="仅显示门禁拦截、P0 退回、熔断与超时异常事件")
    p_logs.add_argument("--event", help="按事件类型过滤（如 gate_block / stuck_cap / task_run / code_review / cron_job）")
    p_logs.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_logs.set_defaults(func=cmd_logs)

    # Subsystem 3: Unified Memory Bus (`init` / `sync` / `promote` / `capture` / `status`)
    p_init = sub.add_parser("init", help="初始化 ~/.paos/brain/ 跨客户端共享记忆与核心规则真源")
    p_init.add_argument("--seed-workspace", help="从现有工作区拷贝初始模板（默认当前 PAOS 仓）")
    p_init.set_defaults(func=cmd_init)

    p_sync = sub.add_parser(
        "sync", help="将 ~/.paos/brain/ 非破坏性同步编译至 Claude / Codex / Antigravity / Cursor 受管块"
    )
    p_sync.add_argument("--targets", help="逗号分隔的目标端（默认自动检测已安装端：claude,codex,antigravity,cursor）")
    p_sync.add_argument("--remove", action="store_true", help="干净移除各端受管块，100%% 保留手写内容")
    p_sync.add_argument("--dry-run", action="store_true", help="仅打印 unified diff 预览，不修改任何文件")
    p_sync.set_defaults(func=cmd_sync)

    p_prm = sub.add_parser("promote", help="扫描 learnings.md 中重复出现的 [tag:...] 坑点并辅助晋升归档")
    p_prm.add_argument("--file", help="指定 learnings.md 路径（默认自动定位当前目录或 ~/.paos/brain/）")
    p_prm.add_argument("--threshold", type=int, default=2, help="触发晋升提醒的最小复发次数（默认 2）")
    p_prm.add_argument("--apply", action="store_true", help="为达标条目追加 `[promoted:YYYY-MM-DD]` 归档标记")
    p_prm.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_prm.set_defaults(func=cmd_promote)

    p_cap = sub.add_parser("capture", help="零 Token 毫秒级把灵感/待办追加进全局或工作区 INBOX.md")
    p_cap.add_argument("text", nargs="+", help="要记录的文本或链接")
    p_cap.add_argument("--workspace", help="指定工作区路径（留空则优先写入 ~/.paos/brain/memory/INBOX.md）")
    p_cap.set_defaults(func=cmd_capture)

    p_st = sub.add_parser("status", help="一屏总览安全分、五端累计税、记忆预算、定时巡检与今日 P0")
    p_st.add_argument("--workspace", help="指定个人 OS 工作区路径")
    p_st.set_defaults(func=cmd_status)

    # Subsystem 4: Isolated Task Scheduler & Cold-Start Goldfish Reviewer (`run` / `review`)
    p_run = sub.add_parser(
        "run", help="跨引擎受控调度器：支持 Git Worktree 物理隔离、进程组超时强杀与预算封顶"
    )
    p_run.add_argument("prompt", nargs="+", help="要派发给 Agent 执行的任务指令")
    p_run.add_argument("--engine", default="auto", choices=["auto", "codex", "claude", "agy"], help="执行引擎")
    p_run.add_argument("-w", "--worktree", action="store_true", help="在 ~/.paos/worktrees/ 新建隔离 Git Worktree 执行")
    p_run.add_argument("--sandbox", default="workspace-write", choices=["workspace-write", "read-only"], help="沙盒读写级别")
    p_run.add_argument("--timeout", type=int, default=600, help="硬超时秒数（超时自动 killpg 强杀整棵子进程树，默认 600s）")
    p_run.add_argument("--max-budget-usd", type=float, default=2.0, help="Claude 单次预算上限美元（默认 2.0）")
    p_run.add_argument("--max-turns", type=int, default=20, help="单次最大轮次上限（默认 20）")
    p_run.add_argument("--model", help="可选指定模型名称")
    p_run.add_argument("--notify", action="store_true", help="任务结束后自动通过通知总线推送结果")
    p_run.add_argument("--dry-run", action="store_true", help="仅预览编译后的底层命令与隔离路径")
    p_run.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_run.set_defaults(func=cmd_run)

    p_rev = sub.add_parser(
        "review", help="金鱼零上下文冷启动盲审：仅喂 Git Diff，检出 [P0] 阻断级缺陷返回退出码 2"
    )
    p_rev.add_argument("--engine", default="auto", choices=["auto", "codex", "claude", "agy"], help="审查引擎")
    p_rev.add_argument("--base", help="对比基准分支（如 main；留空则审查当前未提交变更）")
    p_rev.add_argument("--xhigh", action="store_true", help="启用最高推理强度（适用涉钱/权限/登录/外发消息变更）")
    p_rev.add_argument("--timeout", type=int, default=300, help="盲审超时秒数（默认 300s）")
    p_rev.add_argument("--dry-run", action="store_true", help="仅预览盲审命令与 Diff 规模")
    p_rev.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p_rev.set_defaults(func=cmd_review)

    # Subsystem 5: Zero-Daemon Native Cron & DLP Notification Bus (`cron` / `notify`)
    p_cron = sub.add_parser("cron", help="零常驻守护进程：托管 macOS launchd / Linux crontab 定时巡检")
    cron_sub = p_cron.add_subparsers(dest="cron_cmd", required=True)
    p_c_ls = cron_sub.add_parser("list", help="列出内置与自定义定时任务的安装状态")
    p_c_ls.add_argument("--json", action="store_true")
    p_c_in = cron_sub.add_parser("install", help="安装定时任务（内置 heartbeat / weekly-hygiene 或自定义任务）")
    p_c_in.add_argument("job", help="任务名（如 heartbeat 或 weekly-hygiene）")
    p_c_in.add_argument("--hour", type=int, help="触发小时 (0-23)")
    p_c_in.add_argument("--minute", type=int, help="触发分钟 (0-59)")
    p_c_in.add_argument("--weekday", type=int, help="可选触发星期 (0=周日 .. 6=周六)")
    p_c_in.add_argument("--cmd", dest="cmd_str", help="可选自定义 Shell 命令")
    p_c_in.add_argument("--dry-run", action="store_true", help="仅预览生成的 launchd plist 或 crontab 条目")
    p_c_rm = cron_sub.add_parser("remove", help="卸载指定定时任务")
    p_c_rm.add_argument("job", help="任务名")
    p_c_rm.add_argument("--dry-run", action="store_true")
    p_c_rn = cron_sub.add_parser("run-now", help="在原子锁保护下立即单次触发指定定时任务")
    p_c_rn.add_argument("job", help="任务名")
    p_c_rn.add_argument("--no-notify", action="store_true", help="本次执行不发送完成通知")
    p_c_rn.add_argument("--dry-run", action="store_true")
    p_cron.set_defaults(func=cmd_cron)

    p_ntf = sub.add_parser(
        "notify", help="零入站端口单向脱敏通知总线（macOS 弹窗 / 飞书卡片 / Telegram / Webhook）"
    )
    p_ntf.add_argument("title", help="通知标题")
    p_ntf.add_argument("message", nargs="+", help="通知正文（自动执行出站密钥脱敏）")
    p_ntf.add_argument("--channel", default="auto", help="通道：auto / macos / feishu / telegram / webhook")
    p_ntf.add_argument("--dry-run", action="store_true", help="仅预览脱敏后的出站消息载荷")
    p_ntf.add_argument("--json", action="store_true")
    p_ntf.set_defaults(func=cmd_notify)

    # Legacy single-harness Claude skill subcommands (100% preserved for compatibility)
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

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
