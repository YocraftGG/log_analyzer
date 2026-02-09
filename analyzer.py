from practice.log_analyzer.reader import load_csv


def extract_external_ip(data):
    return [line[1] for line in data if not line[1].startswith("192.168") and not line[1].startswith("10")]

def filter_by_port(data):
    return [line for line in data if line[3] == "22" or line[3] == "23" or line[3] == "3389"]