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
    return {line_i[1]:sum([1 for line_j in data if line_j[1] == line_i[1]]) for index, line_i in enumerate(data) if line_i[1] not in [line_j[1] for line_j in data[:index]]}

def map_port_to_protocol(data):
    return {line[3]:line[4] for line in data}