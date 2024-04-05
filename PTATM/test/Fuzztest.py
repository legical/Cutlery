import sys
sys.path.append("..")
from Fuzz import FuzzEnv

def test_saveCases(input, output):
    return FuzzEnv.CaseTool.saveCases(input, output)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Fuzz test')
    # parser.add_argument('target_path', help='Path to the target program')
    # parser.add_argument('-f', '--function', help='funtion name', required=False, default='main')
    parser.add_argument('-i', '--input', help='Path to input Fuzz test cases', required=True)
    parser.add_argument('-o', '--output', help='Path to save Fuzz test cases', required=True)
    args = parser.parse_args()

    file_path = test_saveCases(args.input, args.output)
    print(f'Generated test cases have been saved to {file_path}.')

    with open(file_path, 'r', encoding="utf-8") as f:
        print(f.read())