#!/usr/bin/env python

import os
import sys
import yaml
import argparse
import subprocess
from datetime import datetime

def load_config(path):
    with open(path) as fd:
        return yaml.load(fd.read())

def has_test_option(gene_path):
    cmd = [gene_path, "-h"]
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if "-test\n" in cp.stderr:
        return True
    return False

def test(config):
    gene_path = config["params"]["gene"]
    rules_path = config["params"]["rules"]
    tests_root = config["params"]["tests-root"]

    if not has_test_option(gene_path):
        print("Gene binary {} does not have -test option, upgrade it")
        sys.exit(1)

    for rule_name, test_file in config["tests"].items():
        fp_test_file = os.path.join(tests_root, test_file)
        #print("Testing rule {}: {}".format(rule_name, test_file))
        cmd = [gene_path, "-test", "-r", rules_path, "-n", rule_name, "-j", test_file]
        start = datetime.now()
        cp = subprocess.run(cmd, capture_output=True, text=True)
        stop = datetime.now()
        delta = stop - start
        if cp.returncode == 0:
            print("Testing {} : SUCCESS (time={}s)".format(rule_name, delta.total_seconds()))
        else:
            print("Stderr:")
            print(str(cp.stderr))
            print("Stdout:")
            print(str(cp.stdout))
            print("Test rule {} : FAILED".format(rule_name))
            sys.exit(cp.returncode)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="Tests configuration file")

    args = parser.parse_args()

    config = load_config(args.config)
    test(config)
