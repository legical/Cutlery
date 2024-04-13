import json
import os

KEY_EXTRACT = 'dump'
KEY_FULLCOST = 'fullcost'
KEY_NORMCOST = 'normcost'
KEY_TIME = 'time'

def json2data(json_file: str, extract_func: str = 'main'):
    # check json file is exist?
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"{json_file} not found")

    with open(json_file, 'r') as file:
        data = json.load(file)

    merged, delseg = list(), list()
    # process data
    if extract_func in data[KEY_EXTRACT]:
        for seg_name, _ in data[KEY_EXTRACT][extract_func].items():
            if seg_name == KEY_FULLCOST:
                continue
            print(f"\nseg_name: {seg_name}")
            seg1, seg2 = seg_name.split('->')
            seg1lastidx, seg2lastidx = seg1.rfind('_'), seg2.rfind('_')
            seg1func, seg2func = seg1[:seg1lastidx], seg2[:seg2lastidx]
            print(f"seg1func: {seg1func}\tseg2func: {seg2func}")
            if seg1func == seg2func and seg2func != extract_func:
                if seg1func in merged:
                    # delete this segname
                    delseg.append(seg_name)
                    print(f"delete seg_name: {seg_name}")
                else:
                    merged.append(seg1func)
                    data[KEY_EXTRACT][extract_func][seg_name][KEY_NORMCOST][KEY_TIME] = data[KEY_EXTRACT][seg1func][KEY_FULLCOST][KEY_TIME]
                    print(f"use {seg1func} instead {seg_name}")

    for seg_name in delseg:
        del data[KEY_EXTRACT][extract_func][seg_name]

    return data

def save2json(data, json_file: str):
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=4)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Fuzz test')
    # parser.add_argument('target_path', help='Path to the target program')
    # parser.add_argument('-f', '--function', help='funtion name', required=False, default='main')
    parser.add_argument('-i', '--input', help='Path to input Fuzz test cases', required=True)
    parser.add_argument('-o', '--output', help='Path to save Fuzz test cases', required=True)
    args = parser.parse_args()

    data = json2data(args.input)
    save2json(data, args.output)