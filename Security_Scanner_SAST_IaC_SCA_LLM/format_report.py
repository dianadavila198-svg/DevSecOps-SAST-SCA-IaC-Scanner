"""
Formats scanner findings (with or without AI enrichment) as a report, 
suitable for posting as a Github PR comment
"""

def format_report_markdown (real_findings, iac_findings, files_scanned):
    """
    real_findings: SAST + SCA findings — genuine issues found in the
    actual UoA Sense Map codebase. Counted in the main total.
    (each has rule_id, severity, file_path, line, message, standard_ref,
    ai_explanation, ai_note/ai_model)

    iac_findings: IaC findings from infra/demo.tf — a demonstration
    file, NOT real infrastructure. Shown in its own separate section,
    NOT included in the main issue count, so the report doesn't
    misleadingly suggest the app has real infrastructure problems.

    files_scanned: int, how many files were scanned

    """
    #Building the report line by line, cleaner to read. 
    #Markdown syntax (##, **bold**, `code`, > blockquote, --- horizontal rule) — 
    #these are exactly what GitHub renders nicely when posted as a PR comment
    lines = []

    lines.append("## 🔎 Security Scanner Results")
    lines.append("")
    lines.append (f"Scanned **{files_scanned}** files.")


#Even when there are zero findings, 'if not' branch will show a 'no issues' message
#so the GitHub Actions step that reads this file doesnt fail with a missing-file error on a clean scan

    if not real_findings:
        lines.append("✅ No security issues found in the repository")
    else:
        lines.append(f"**{len(real_findings)} issue(s) found:**")
        lines.append("")

        for item in real_findings:
            #Appending Rule ouptut format 
            lines.append(f"### [{item['severity']}] `{item['rule_id']}`")
            lines.append(f"**File:** `{item['file_path']}:{item['line']}`")
            lines.append(f"**Attack Type Exposure:** {item['attack_type_exposure']}")
            lines.append(f"**Standard:** {item['standard_ref']}")
            lines.append("")
            lines.append(f"> {item['message']}")
            lines.append("")

            if item.get ("ai_explanation"):
                lines.append(f"**AI Explanation** _(via {item['ai_model']})_:")
                lines.append(item["ai_explanation"])
            else:
                lines.append(f"_{item.get('ai_note', 'AI enrichment unavailable.')}_")

            lines.append("")
            lines.append("---")
            lines.append("")

    #---IaC section — kept separate from real_findings above on purpose---
    #infra/demo.tf is a demonstration file only (see infra/demo.tf's own
    #header comment) — these findings prove the Checkov integration
    #works, they are NOT real issues in the Sense Map application itself.
    lines.append("")
    lines.append("## 🧪 IaC Pillar — Demonstration Findings")
    lines.append("")
    lines.append(
        "_UoA Sense Map does not currently provision infrastructure via "
        "Terraform. The findings below are from `infra/demo.tf`, a "
        "deliberately-configured demonstration file used to verify the "
        "Checkov integration works end-to-end. These are NOT real "
        "infrastructure issues and are not included in the issue count above._"
    )
    lines.append("")

    if not iac_findings:
        lines.append("No findings from the demonstration file.")
    else:
        lines.append(f"**{len(iac_findings)} demonstration finding(s):**")
        lines.append("")

        for item in iac_findings:
            lines.append(f"### [{item['severity']}] `{item['rule_id']}`")
            lines.append(f"**File:** `{item['file_path']}:{item['line']}`")
            lines.append(f"**Standard:** {item['standard_ref']}")
            lines.append("")
            lines.append(f"> {item['message']}")
            lines.append("")
            lines.append(f"_{item.get('ai_note', '')}_")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)