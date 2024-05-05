import subprocess

class TraceCollector:
    # probe vars.
    PGROUP          = "ETCG"
    PROBE_PREFIX    = PGROUP + ':'
    PROBE_ALL       = PROBE_PREFIX + '*'
    RECORD_FILE     = "/tmp/PTATM-ETCG-record"

    @staticmethod
    def exec(shellcmd: str) -> bool:
        result = subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return 0 == result.returncode

    @staticmethod
    def execWithResult(shellcmd: str, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        return subprocess.run(shellcmd, shell=True, stdout=stdout, stderr=stderr)

    @staticmethod
    def addprobe(binary: str, probe: str) -> bool:
        cmd = "perf probe -x " + binary + " -a " + probe
        # print("addprobe:", cmd)
        return TraceCollector.exec(cmd)

    @staticmethod
    def delprobe(probe: str) -> bool:
        return TraceCollector.exec("perf probe -d " + probe)
    
    @staticmethod
    def showprobe(binary: str) -> bool:
        cmd = f"perf probe -l"
        probe_info = TraceCollector.execWithResult(cmd)
        if probe_info.returncode != 0:
            raise Exception(f"Failed exec [{cmd}].\n[Error]: {probe_info.stderr.decode('utf-8')}")
        print(f"binary[{binary}] probes:\n{probe_info.stdout.decode('utf-8')}\n")

    @staticmethod
    def fetchSegmentAndTime(traceinfo: str) -> str:
        pure = str()
        for trace in [record.strip() for record in traceinfo.strip().split('\n')]:
            info = trace.strip().split(' ')
            time = info[0][:-1]
            segname = info[-1][5:-1]
            pure += time + ',' + segname + '\n'
        return pure

    # Returns (True, trace) or (False, error message).
    @staticmethod
    def collectTrace(command: str) -> tuple:
        record = "perf record -e %s -aR -o %s %s" % (TraceCollector.PROBE_ALL, TraceCollector.RECORD_FILE, command)
        script = "perf script -F time,event -i %s" % TraceCollector.RECORD_FILE

        # Use perf record to collect trace.
        record_result = TraceCollector.execWithResult(record, stdout=subprocess.DEVNULL)
        if record_result.returncode != 0:
            return (False, f"Record [{record}] failed!\n{record_result.stderr.decode('utf-8')}")
        # if not TraceCollector.exec(record):
        #     return (False, "Record command " + command + " failed. " + record)

        # Use perf script to dump trace.
        traceinfo_result = TraceCollector.execWithResult(script)
        if traceinfo_result.returncode != 0:
            return (False, "Cat trace file failed: " + script)
        
        # Fetch trace info from perf script result.
        return (True, TraceCollector.fetchSegmentAndTime(traceinfo_result.stdout.decode('utf-8')))
