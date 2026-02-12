from analyzer import total_lines_read, total_lines_suspected, total_lines_external, total_lines_sensitive, \
    total_lines_large, total_lines_night


def generate_report(suspicious_dict):
    yield "=======================================\n"
    yield "       לוח תעבורה חשודה\n"
    yield "=======================================\n"
    yield "\n"
    yield "סטטיסטיקות כלליות:\n"
    yield f"שורות שנקראו: {total_lines_read} -\n"
    yield f"שורות חשודות: {total_lines_suspected} -\n"
    yield f"- EXTERNAL_IP: {total_lines_external}\n"
    yield f"- SENSITIVE_PORT: {total_lines_sensitive}\n"
    yield f"- LARGE_PACKET: {total_lines_large}\n"
    yield f"- NIGHT_ACTIVITY: {total_lines_night}\n"
    yield "\n"
    yield "IPs עם רמת סיכון גבוהה (3+ חשדות):\n"
    for ip, suspicious in suspicious_dict.items():
        if len(suspicious) >= 3:
            yield f"- {ip}: {", ".join(suspicious)}\n"
    yield "\n"
    yield "IPs חשודים נוספים:\n"
    for ip, suspicious in suspicious_dict.items():
        if len(suspicious) < 3:
            yield f"- {ip}: {", ".join(suspicious)}\n"