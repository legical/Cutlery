import os
import shutil


class FuzzEnv:
    # [Attribute]
    #   segment_info            A list, segment address offset.
    #   in_path                 file path of AFL fuzz seeds.
    #   out_path                file path of save test cases.
    #   afl_cmds                additional AFL commands.
    # [Member]
    #   get_node                Get CFG node by addr.

    # init
    def __init__(self, in_path:str, out_path:str, seg_path:str, binary:str):
        self.in_path = in_path
        self.out_path = out_path
        self.seg_path = seg_path
        self.binary = binary
        # self.afl_cmds = afl_cmds
        self.seginfo = []
        self.afl_root = os.environ.get('AFL_ROOT_PATH', '/usr/local/bin/')

    # Delete all files&folders
    def __cleanPath(self, path):
        if os.path.exists(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))

    # Check if the folder exists, if not, create the directory
    def __checkPathExist(self, path:str, clear = False):
        if not os.path.exists(path):
            os.makedirs(path)
        elif clear:
            self.__cleanPath(path)

    # Check if the file exists, if not, raise a FileNotFoundError
    def __checkFileExist(self, path:str):
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} does not exist.")

    # Check if the input folder exists, if not, create the directory
    def __checkInPathExist(self, clear = False):
        self.__checkPathExist(self.in_path, clear)
    
    # Check if the output folder exists, if not, create the directory
    def __checkOutPathExist(self, clear = False):
        self.__checkPathExist(self.out_path, clear)

    # Check if the output folder exists, if not, create the directory
    # if it exists, check if the folder is empty, if it is not empty, report an error
    def __checkOutPathEmpty(self):
        self.__checkOutPathExist()
    
        if len(os.listdir(self.out_path)) != 0:
            # ask user whether to delete the files in the folder
            # if user choose to delete, delete all files and folders in the folder
            if input("The output folder[%s] is not empty, do you want to delete all files? [y/n]" % self.out_path) == "y":
                self.__cleanPath(self.out_path)
            else:
                raise Exception("Exit! Output folder[%s] is not empty." % self.out_path)
            
    # Check Workspace (in/out folder) exist?
    def checkWorkspaceExist(self):
        self.__checkInPathExist()
        self.__checkOutPathExist()

    # Check if AFL tool: afl-fuzz exist?
    def checkAFLExist(self):
        afl_fuzz_path = os.path.join(self.afl_root, "afl-fuzz")
        self.__checkFileExist(afl_fuzz_path)

    # Check CPU frequency scaling governor
    def checkCPUFreqScaling(self):
        if os.getenv("AFL_SKIP_CPUFREQ"):
            return

        scaling_governor_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        scaling_min_freq_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq"
        scaling_max_freq_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"

        try:
            with open(scaling_governor_path, "r") as f:
                scaling_governor = f.readline().strip()
        except FileNotFoundError:
            return

        if scaling_governor.startswith("perf"):
            return

        min_freq = 0
        max_freq = 0

        try:
            with open(scaling_min_freq_path, "r") as f:
                min_freq = int(f.readline())
        except FileNotFoundError:
            pass

        try:
            with open(scaling_max_freq_path, "r") as f:
                max_freq = int(f.readline())
        except FileNotFoundError:
            pass

        if min_freq == max_freq:
            return

        print(f"\n[-] Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
              f"    between {min_freq // 1024} and {max_freq // 1024} MHz. Unfortunately, the scaling algorithm in the\n"
              f"    kernel is imperfect and can miss the short-lived processes spawned by\n"
              f"    afl-fuzz. To keep things moving, run these commands as root:\n\n"
              f"    cd /sys/devices/system/cpu\n"
              f"    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"
              f"    You can later go back to the original state by replacing 'performance' with\n"
              f"    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
              f"    to make afl-fuzz skip this check - but expect some performance drop.\n")

        os.environ["AFL_SKIP_CPUFREQ"] = "1"
        print("Auto export AFL_SKIP_CPUFREQ=1 to skip CPU frequency check.")
        print("You can manually export the environment variable as well.")

    # 检查系统是否配置为将核心转储通知发送到外部实用程序
    def checkCoreDump(self):
        if os.getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"):
            return

        if os.name == "posix":
            core_pattern_path = "/proc/sys/kernel/core_pattern"
            try:
                with open(core_pattern_path, "r") as f:
                    core_pattern = f.read(1)
            except FileNotFoundError:
                return

            if core_pattern == "|":
                print("\n[-] Hmm, your system is configured to send core dump notifications to an\n"
                      "    external utility. This will cause issues: there will be an extended delay\n"
                      "    between stumbling upon a crash and having this information relayed to the\n"
                      "    fuzzer via the standard waitpid() API.\n\n"
                      "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
                      "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"
                      "    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1\n\n"
                      "    With this environment variable, AFL will not display warning messages and may miss crashes. You can also:\n"
                      "    sudo su\n"
                      "    echo core >/proc/sys/kernel/core_pattern\n")

                if not os.getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"):
                    raise Exception("Pipe at the beginning of 'core_pattern'")
        else:
            print("This check is specific to Linux and is not supported on your system.")
    
    # Init: Workspace (in/out folder) exist, out empty?
    def initWorkspace(self):
        self.checkWorkspaceExist()
        self.__checkOutPathEmpty()
        self.checkAFLExist()
        # Check binary file exist?
        self.__checkFileExist(self.binary)
        # Check segment file exist?
        self.__checkFileExist(self.seg_path)
        # Check AFL run envrionment
        self.checkCoreDump()
        self.checkCPUFreqScaling()
                
    # get segment info from file, only save segment address offset with main%
    # args: prefix, default is "main", function name
    # return a list, each element is a segment address offset
    def getSegInfo(self, prefix = "main") -> list:
        # 检查文件是否存在
        try:
            with open(self.seg_path, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            self.seginfo.append("return")
            return self.seginfo

        # 提取符合条件的数值
        values = []
        separators = [',', '\n', '=']
        for separator in separators:
            content = content.replace(separator, ' ')
        words = content.split()
        for word in words:
            if word.startswith(prefix + "+0x"):
                value_dec = int(word[len(prefix) + 3:], 16)
                value = hex(value_dec)
                values.append(value)

        # 按照从小到大的顺序排列
        values.sort()

        # 添加数值到结果列表
        self.seginfo.extend(values)

        # 在列表末尾插入"return"
        self.seginfo.append("return")

        return self.seginfo

    # save old out seeds, move self.out_path to self.out_path_old/time
    # time is the current time
    def saveOldOutSeeds(self):
        # 获取当前时间
        import time, subprocess
        time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        
        # 创建old文件夹
        self.old_out_path = self.out_path + "_old"
        self.__checkPathExist(self.old_out_path)

        # 保存本次输出的文件夹
        thisold = self.old_out_path + "/" + time
        mv2old = f"mv {self.out_path} {thisold}"
        process = subprocess.Popen(['bash', '-c', mv2old], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 等待命令结束
        process.wait()
        # os.rename(self.out_path, self.out_path + "_old/" + time)

        # 创建新的输出文件夹
        self.__checkOutPathExist(True)

    # copy only files, not subfolders of out_path/queue/* to in_path, rename file with prefix(segment address offset)
    def mergeSeeds(self, prefix = ""):
        queue_path = self.out_path + "/queue"
        if os.path.exists(queue_path):
            # 获取out_path/queue/下的所有文件，但不包括子文件夹及其内部的文件
            files = [f for f in os.listdir(queue_path) if os.path.isfile(os.path.join(queue_path, f))]

            self.__checkInPathExist(True)

            # 复制生成的测试用例到输入文件夹
            for i, file_name in enumerate(files, 1):
                # 构造新的文件名，例如1.in、2.in、3.in等
                new_file_name = f"{i}.in"

                src = queue_path + "/" + file_name
                dst = self.in_path + "/" + prefix + new_file_name
                shutil.copyfile(src, dst)

            # 保存本次输出seeds
            self.saveOldOutSeeds()

    
    