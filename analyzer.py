from config import *
from reader import *


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

def is_night_activity(hour):
    if NIGHT_ACTIVITY[0] < NIGHT_ACTIVITY[1]:
        return NIGHT_ACTIVITY[0] <= hour < NIGHT_ACTIVITY[1]
    else:
        return NIGHT_ACTIVITY[0] <= hour < 0 or hour < NIGHT_ACTIVITY[1]

def suspicions(line):
    lst = []
    if not (line[1].startswith("192.168") or line[1].startswith("10")):
        lst.append("IP_EXTERNAL")
    if line[3] in SENSITIVE_PORTS:
        lst.append("PORT_SENSITIVE")
    if int(line[5]) > SIZE:
        lst.append("PACKET_LARGE")
    if is_night_activity(int(line[0].split(" ")[1].split(":")[0])):
        lst.append("ACTIVITY_NIGHT")

    return lst

def identifying_suspicions(data):
    return {line[1]:suspicions(line) for line in data if suspicions(line)}

def filter_suspicions(suspects):
    return {ip:suspicions for ip, suspicions in suspects.items() if len(suspicions) >= 2}

def extract_hours(timestamps):
    return list (map(lambda timestamp: int(timestamp.split(" ")[1].split(":")[0]), timestamps))

def bytes_to_kilobytes(bytes_):
    return list(map(lambda byte: round(float(byte) / 1024, 1), bytes_))

def filter_by_port_map(data):
    return list(filter(lambda line: line[3] in SENSITIVE_PORTS, data))

def filter_night_activity(data):
    return list(filter(lambda line: is_night_activity(int(line[0].split(" ")[1].split(":")[0])), data))

suspicion_checks = { "EXTERNAL_IP": lambda line: not (line[1].startswith("192.168") or line[1].startswith("10")),
"SENSITIVE_PORT": lambda line: line[3] in SENSITIVE_PORTS, "LARGE_PACKET":
lambda line: int(line[5]) > SIZE, "NIGHT_ACTIVITY": lambda line: is_night_activity(int(line[0].split(" ")[1].split(":")[0]))}

def line_checks(line, checks):
    return list(map(lambda sus: sus[0], filter(lambda sus: sus[1](line), checks.items())))

data_checks = list(filter(lambda suspicions: suspicions,map(lambda line: line_checks(line, suspicion_checks), load_csv("network_traffic.log"))))

def filter_suspicious(lines):
    for line in lines:
        if suspicions(list(line)):
            yield line

def add_suspicion_details(lines):
    for line in lines:
        if suspicions(list(line)):
            yield list(line), suspicions(list(line))

def count_items(lines):
    return sum(1 for line in lines if suspicions(list(line)))