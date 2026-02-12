from config import *
from reader import *


total_lines_read = 0
total_lines_suspected = 0
total_lines_external = 0
total_lines_sensitive = 0
total_lines_large = 0
total_lines_night = 0


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
        lst.append("EXTERNAL_IP")
    if line[3] in SENSITIVE_PORTS:
        lst.append("SENSITIVE_PORT")
    if int(line[5]) > SIZE:
        lst.append("LARGE_PACKET")
    if is_night_activity(int(line[0].split(" ")[1].split(":")[0])):
        lst.append("NIGHT_ACTIVITY")

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

def filter_suspicious(lines):
    for line in lines:
        if suspicions(list(line)):
            yield line

def add_suspicion_details(lines):
    for line in lines:
        if suspicions(list(line)):
            yield list(line), suspicions(list(line))

def count_items(lines):
    return sum(1 for _ in lines)

def update_statistics(filepath):
    global total_lines_read
    global total_lines_suspected
    global total_lines_external
    global total_lines_sensitive
    global total_lines_large
    global total_lines_night

    lines = list(read_log(filepath))
    total_lines_read = count_items(lines)

    suspicious = list(filter_suspicious(lines))
    total_lines_suspected = count_items(suspicious)

    external = extract_external_ip(suspicious)
    sensitive = filter_by_port(suspicious)
    large = filter_by_size(suspicious)
    night = filter_night_activity(suspicious)

    total_lines_external = count_items(external)
    total_lines_sensitive = count_items(sensitive)
    total_lines_large = count_items(large)
    total_lines_night = count_items(night)

def analyze_log(filepath):
    lines = read_log(filepath)
    suspicious = filter_suspicious(lines)
    details = add_suspicion_details(suspicious)
    dict_ip_suspicions = identifying_suspicions(list(read_log(filepath)))
    filtered_ips = filter_suspicions(dict_ip_suspicions)
    update_statistics(filepath)
    return filtered_ips