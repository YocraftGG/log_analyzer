import csv

def load_csv(path):
    with open(path) as f:
        return list(csv.reader(f))