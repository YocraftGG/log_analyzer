def extract_external_ip(data):
    return [line[1] for line in data if not line[1].startswith("192.168") and not line[1].startswith("10")]