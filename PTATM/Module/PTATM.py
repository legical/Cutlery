import datetime
import os
import subprocess
import sys


# 获取当前被执行.py文件的绝对目录的父目录
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root = os.getenv('PTATM', parent_dir)


def exec(shellcmd: str) -> bool:
    return 0 == subprocess.run(shellcmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def execWithResult(shellcmd: str):
    return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def issudo() -> bool:
    return os.getuid() == 0


def report(s: str):
    sys.stdout.write('[%s] %s\n' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), s))


def info(s: str):
    report('[INFO] %s' % s)


def warn(s: str):
    report('[WARN] %s' % s)


def error(s: str):
    report('[ERROR] %s' % s)


def fileEndWith(file_path: str, suffix: str) -> str:
    """
    Returns a new file path with the specified suffix. If the file path already ends with the suffix, the file path will not be changed.

    Args:
        file_path (str): The original file path.
        suffix (str): The suffix to be added to the file path. Must be like .xxx

    Returns:
        str: The new file path with the specified suffix.
    """
    if not file_path.endswith(suffix):
        last_dot_index = file_path.rfind('.')

        if last_dot_index != -1:
            new_file_path = file_path[:last_dot_index] + suffix
            return new_file_path
        else:
            return file_path + suffix
