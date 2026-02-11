import csv
from config import *

def load_csv(path):
    with open(path) as f:
        return list(csv.reader(f))

def load_csv_generator(path):
    with open(path) as f:
        for line in f:
            yield line.strip().split(',')