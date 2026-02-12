import analyzer


def generate_report(suspicious_dict):
    report = "=======================================\n"
    report += "       לוח תעבורה חשודה\n"
    report += "=======================================\n"
    report += "\n"
    report += "סטטיסטיקות כלליות:\n"
    report += f"שורות שנקראו: {analyzer.total_lines_read} -\n"
    report += f"שורות חשודות: {analyzer.total_lines_suspected} -\n"
    report += f"- EXTERNAL_IP: {analyzer.total_lines_external}\n"
    report += f"- SENSITIVE_PORT: {analyzer.total_lines_sensitive}\n"
    report += f"- LARGE_PACKET: {analyzer.total_lines_large}\n"
    report += f"- NIGHT_ACTIVITY: {analyzer.total_lines_night}\n"
    report += "\n"
    report += "IPs עם רמת סיכון גבוהה (3+ חשדות):\n"
    for ip, suspicious in suspicious_dict.items():
        if len(suspicious) >= 3:
            report += f"- {ip}: {", ".join(suspicious)}\n"
    report += "\n"
    report += "IPs חשודים נוספים:\n"
    for ip, suspicious in suspicious_dict.items():
        if len(suspicious) < 3:
            report += f"- {ip}: {", ".join(suspicious)}\n"
    return report

def save_report(report, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        for line in report:
            f.write(line)