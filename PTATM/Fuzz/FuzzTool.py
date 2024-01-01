import subprocess


class FuzzTool:
    def __init__(self, AFL_ROOT_PATH = "/usr/local/bin/") -> None:
        self.afl_fuzz = AFL_ROOT_PATH + "afl-fuzz"
        self.afl_tmin = AFL_ROOT_PATH + "afl-tmin"
        self.afl_qemu_trace = AFL_ROOT_PATH + "afl-qemu-trace"

    # generate AFL Command Line Prefixes
    def genPreAFLCmd(self, in_path:str, out_path:str, seg_info:str) -> str:
        # format cmd str
        pre_afl_cmd = f"{self.afl_fuzz} -i {in_path} -o {out_path} -s {seg_info}"
        return pre_afl_cmd    

    # generate AFL Command Line Suffixes
    def genSufAFLCmd(self, binary:str, readFile = False, binary_args = "") -> str:
        # format cmd str
        suf_afl_cmd = f" -Q {binary} {binary_args}"
        if readFile:
            suf_afl_cmd += " @@"
        return suf_afl_cmd

    # generate AFL Command Line
    def genAFLCmd(self, pre_afl_cmd:str, suf_afl_cmd:str, extra_afl_cmd = "") -> str:
        # combine cmd str afl_cmds + extra-afl-cmd + f" -Q {self.binary}" + @@
        afl_cmd = pre_afl_cmd + extra_afl_cmd + suf_afl_cmd
        return afl_cmd
        
    # run AFL command with wait mode
    def run_command(self, afl_cmds:str):
        # 启动bash AFL fuzz
        process = subprocess.Popen(['bash', '-c', afl_cmds], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 等待命令结束
        process.wait()

        # 获取命令的退出码
        exit_code = process.returncode

        # 返回命令的退出码
        return exit_code
    
    def fuzzone(self, afl_cmds:str):
        self.run_command(afl_cmds)


