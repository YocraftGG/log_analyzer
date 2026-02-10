from config import *
from reader import load_csv


def extract_external_ip(data):
    return [line[1] for line in data if not line[1].startswith("192.168") and not line[1].startswith("10")]

def filter_by_port(data):
    return [line for line in data if line[3] in SENSITIVE_PORTS]

def filter_by_size(data):
    return [line for line in data if int(line[5]) > SIZE]

def tag_traffic(data):
    return [line + ["LARGE"] if int(line[5]) > SIZE else line + ["NORMAL"] for line in data]

def count_ip_calls(data):
    return {line_i[1]:sum([1 for line_j in data if line_j[1] == line_i[1]])
            for index, line_i in enumerate(data)
            if line_i[1] not in [line_j[1] for line_j in data[:index]]}

def map_port_to_protocol(data):
    return {line[3]:line[4] for line in data}

def suspicions(line):
    lst = []
    if not (line[1].startswith("192.168") or line[1].startswith("10")):
        lst.append("IP_EXTERNAL")
    if line[3] in SENSITIVE_PORTS:
        lst.append("PORT_SENSITIVE")
    if int(line[5]) > SIZE:
        lst.append("PACKET_LARGE")
    hour = int(line[0].split(" ")[1].split(":")[0])
    if NIGHT_ACTIVITY[0] < NIGHT_ACTIVITY[1]:
        if NIGHT_ACTIVITY[0] <= hour < NIGHT_ACTIVITY[1]:
            lst.append("ACTIVITY_NIGHT")
    else:
        if NIGHT_ACTIVITY[0] <= hour < 0 or hour < NIGHT_ACTIVITY[1]:
            lst.append("ACTIVITY_NIGHT")
    return lst

def identifying_suspicions(data):
    return {line[1]:suspicions(line) for line in data if suspicions(line)}

def filter_suspicions(suspects):
    return {ip:suspicions for ip, suspicions in suspects.items() if len(suspicions) >= 2}

def extract_hours(timestamps):
    return list (map(lambda timestamp: int(timestamp.split(" ")[1].split(":")[0]), timestamps))