import sys
import argparse

from hashdb import algorithms


class AlgorithmError(Exception):
    pass


def list_algorithms():
    return list(algorithms.modules.keys())


def hash_data(algorithm_name, data):
    if algorithm_name not in list(algorithms.modules.keys()):
        raise AlgorithmError("Algorithm not found")
    if data is str:
        data = data.encode('utf-8')
    return algorithms.modules[algorithm_name].hash(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("algorithm_name", type=str, choices=list_algorithms())
    args = parser.parse_args()
    while line := sys.stdin.buffer.readline():
        data = line.strip(b'\n')
        val = hash_data(args.algorithm_name, data)
        print(f'{data.decode()},{val:#08x}')


if __name__ == "__main__":
    main()
