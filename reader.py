import csv
from config import *

def load_csv(path):
    with open(path) as f:
        return list(csv.reader(f))

