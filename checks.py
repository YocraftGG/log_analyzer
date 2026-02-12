from config import *
from analyzer import is_night_activity
from reader import load_csv

suspicion_checks = { "EXTERNAL_IP": lambda line: not (line[1].startswith("192.168") or line[1].startswith("10")),
"SENSITIVE_PORT": lambda line: line[3] in SENSITIVE_PORTS, "LARGE_PACKET":
lambda line: int(line[5]) > SIZE, "NIGHT_ACTIVITY": lambda line: is_night_activity(int(line[0].split(" ")[1].split(":")[0]))}

def line_checks(line, checks):
    return list(map(lambda sus: sus[0], filter(lambda sus: sus[1](line), checks.items())))

data_checks = list(filter(lambda suspicions: suspicions,map(lambda line: line_checks(line, suspicion_checks), load_csv("network_traffic.log"))))