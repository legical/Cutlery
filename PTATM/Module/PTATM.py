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

