import datetime
import os
import shutil
import angr
import chardet


class AFLConfig:
    # 设置环境的命令提示
    help = """
    Execute the following commands to set up AFL environment:

    1. Get superuser privileges:
       sudo su

    2. Configure the core dump pattern to eliminate error reporting:
       echo core > /proc/sys/kernel/core_pattern

    3. Switch to the CPU device directory:
       cd /sys/devices/system/cpu

    4. Set the frequency adjustment policy for all CPUs to 'performance' mode:
       echo performance | tee cpu*/cpufreq/scaling_governor
    
    5. Exit superuser privileges:
       exit
    """

    @staticmethod
    # Check CPU frequency scaling governor
    def checkCPUFreqScaling():
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

    @staticmethod
    # 检查系统是否配置为将核心转储通知发送到外部实用程序
    def checkCoreDump():
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

    @staticmethod
    def initEnvPrompt(prompt: str = help):
        lines = prompt.strip().split('\n')
        max_width = max(len(line) for line in lines)+5
        border = '+' + '-' * (max_width + 2) + '+'

        box_str = border + '\n'
        box_str += '| ' + 'AFL Startup Setup Tip'.center(max_width) + ' |\n'
        box_str += border + '\n'

        # 按行分割命令字符串，并添加到美化后的字符串中
        for line in lines:
            box_str += '| ' + line.strip().ljust(max_width) + ' |\n'

        box_str += border + '\n'
        print(box_str)

    @staticmethod
    def checkAFLInitEnv():
        AFLConfig.initEnvPrompt(AFLConfig.help)
        # 询问用户是否已经按照提示输入了命令
        user_input = input(
            "Please enter 'y' to continue, other to exit: ")

        # 判断用户输入并作出相应处理
        if user_input.lower() != 'y':
            raise RuntimeError("Error: Please follow the prompts to execute the AFL initialization command correctly.")

        AFLConfig.checkCoreDump()
        AFLConfig.checkCPUFreqScaling()

    @staticmethod
    def getAFLRoot() -> str:
        return os.environ.get('AFL_ROOT_PATH', '/usr/local/bin/')


class Seginfo:
    @staticmethod
    def genCFG(binary_path: str):
        # 初始化 Angr 项目
        proj = angr.Project(binary_path, auto_load_libs=False)

        # 使用 CFGFast 分析二进制程序
        cfg = proj.analyses.CFGFast()
        cfg.normalize()

        return cfg

    @staticmethod
    def getFuncRetAddr(cfg, func_name: str) -> int:
        # 获取函数对象
        func = cfg.kb.functions.function(name=func_name)
        # 返回函数的返回地址
        ret_addr = func.endpoints[0].addr if func.endpoints else None
        return ret_addr

    @staticmethod
    def getFuncStartAddrs(cfg) -> dict:
        function_addrs = dict()
        for func in cfg.kb.functions.values():
            func_start_addr = func.addr
            function_addrs[func.name] = func_start_addr

        return function_addrs

    @staticmethod
    def getSegInfo(seg_path: str = None, binary_path: str = None) -> list:
        if not os.path.exists(seg_path):
            return ['return']
        with open(seg_path, 'r') as file:
            content = file.read()

        cfg = Seginfo.genCFG(binary_path)
        function_addrs = Seginfo.getFuncStartAddrs(cfg)
        equations = content.strip().split(',')
        seginfo = []

        for eq in equations:
            _, seg_name = eq.split('=')
            seg_name = seg_name.strip()
            if '+' in seg_name:
                # 一般基本块地址 seg_name=func_name+offset
                function_name, offset = seg_name.split('+')
                offset = int(offset, 16)  # 转换16进制的偏移量为整数
                seg_addr = function_addrs[function_name] + offset
            elif r'%return' in seg_name:
                # 返回地址 seg_name=func_name%return
                function_name, _ = seg_name.split(r'%')
                seg_addr = Seginfo.getFuncRetAddr(cfg, function_name) if function_name != 'main' else 0
            else:
                # 起始地址 seg_name=func_name，去除main__0=main
                seg_addr = function_addrs[seg_name] if seg_name != 'main' else None

            if seg_addr is not None:
                seginfo.append(hex(seg_addr))

        return seginfo


class FileTool:
    @staticmethod
    def isExist(path: str, raise_exception=False):
        """
        Check if the specified path/file exists.

        Args:
            path (str): The path/file to check.

        Returns:
            bool: True if the path/file exists, False otherwise.
        """
        state = os.path.exists(path)
        if not state and raise_exception:
            raise FileNotFoundError(f"File or Path [{path}] does not exist.")
        return state

    @staticmethod
    def cleanPath(path: str):
        """
        Removes all files and directories within the specified path.

        Args:
            path (str): The path to clean.
        """
        if FileTool.isExist(path):
            shutil.rmtree(path)
        FileTool.mkdirPath(path)

    @staticmethod
    def mkdirPath(path: str):
        """
        Create a directory at the specified path if it doesn't already exist.

        Args:
            path (str): The path of the directory to be created.
        """
        if not os.path.exists(path):
            os.makedirs(path)


class CheckEnv:
    @staticmethod
    def help():
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

    @staticmethod
    def checkOutPathEmpty(out_path: str):
        """
        Checks if the output path is empty and prompts the user to delete its contents if not.

        Args:
            out_path (str): The path to the output folder.

        Raises:
            Exception: If the user chooses not to delete the files in the folder.

        """
        FileTool.mkdirPath(out_path)

        if len(os.listdir(out_path)) != 0:
            # ask user whether to delete the files in the folder
            # if user choose to delete, delete all files and folders in the folder
            if input("The output folder[%s] is not empty, do you want to delete all files? [y/n]" % out_path) == "y":
                FileTool.cleanPath(out_path)
            else:
                raise Exception("Exit! Output folder[%s] is not empty." % out_path)

    @staticmethod
    def checkWorkspaceExist(in_path: str, out_path: str):
        """
        Check if the input and output directories exist.

        Args:
            in_path (str): The path of the input directory.
            out_path (str): The path of the output directory.

        Returns:
            None
        """
        FileTool.mkdirPath(in_path)
        CheckEnv.checkOutPathEmpty(out_path)

    @staticmethod
    def checkAFLExist(afl_root: str):
        """
        Check if the AFL tool is installed.

        Args:
            afl_root (str): The path of the AFL tool.

        Returns:
            None
        """
        afl_fuzz_path = os.path.join(afl_root, "afl-fuzz")
        FileTool.isExist(afl_fuzz_path, True)

    @staticmethod
    def checkBinaryExist(binary: str):
        """
        Check if the binary file exists.

        Args:
            binary (str): The path of the binary file.

        Returns:
            None
        """
        FileTool.isExist(binary, True)

    @staticmethod
    def checkWorkspace(in_path: str, out_path: str, binary: str):
        """
        Check the input and output directories, the AFL tool, and the binary file.

        Args:
            in_path (str): The path of the input directory.
            out_path (str): The path of the output directory.
            afl_root (str): The path of the AFL tool.
            binary (str): The path of the binary file.

        Returns:
            None
        """
        AFLConfig.checkAFLInitEnv()
        CheckEnv.checkWorkspaceExist(in_path, out_path)
        afl_root = AFLConfig.getAFLRoot()
        CheckEnv.checkAFLExist(afl_root)
        CheckEnv.checkBinaryExist(binary)


class CaseTool:
    @staticmethod
    def onlySaveSeeds(out_path: str):
        # 创建old文件夹
        old_out_path = out_path + "_old"
        queue_path = out_path + "/queue"
        FileTool.mkdirPath(old_out_path)
        # 保存本次输出的seeds
        cases_file = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        cases_file_path = os.path.join(old_out_path, f"{cases_file}.txt")
        
        test_cases = CaseTool.saveCases(queue_path)        
        # 将聚合后的测试用例内容写入到输出文件中
        with open(cases_file_path, "a", encoding="utf-8") as output_file:
            output_file.write(test_cases)
        # 创建新的输出文件夹
        FileTool.cleanPath(out_path)
        
        return cases_file_path

    @staticmethod
    # copy only files, not subfolders of out_path/queue/* to in_path, rename file with prefix(segment address offset)
    def mergeSeeds(in_path: str, out_path: str, prefix=""):
        queue_path = out_path + "/queue"
        if os.path.exists(queue_path):
            # 获取out_path/queue/下的所有文件，但不包括子文件夹及其内部的文件
            files = [f for f in os.listdir(queue_path) if os.path.isfile(os.path.join(queue_path, f))]
            FileTool.cleanPath(in_path)
            # 复制生成的测试用例到输入文件夹
            for i, file_name in enumerate(files, 1):
                # 构造新的文件名，例如1.in、2.in、3.in等
                new_file_name = f"{i}.in"

                src = queue_path + "/" + file_name
                dst = in_path + "/" + prefix + new_file_name
                shutil.copyfile(src, dst)

    @staticmethod
    def saveCases(case_path: str) -> str:
        # check input path exist?
        FileTool.isExist(case_path, True)
        
        # copy all .in files in in_path to cases_file
        test_cases = ""
        for filename in os.listdir(case_path):
            if filename.endswith(".in"):
                with open(os.path.join(case_path, filename), "rb") as file:  # 以二进制模式打开文件
                    raw_data = file.read()
                    detected_encoding = chardet.detect(raw_data)['encoding']
                    if detected_encoding:
                        test_cases += raw_data.decode(detected_encoding)
                    else:
                        # 如果无法检测编码，则默认使用UTF-8
                        test_cases += raw_data.decode("utf-8", errors="replace")
                    test_cases += '\n'
                    
        return test_cases
        
