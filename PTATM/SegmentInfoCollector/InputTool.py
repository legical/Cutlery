import json


class InputJson:
    def __init__(self, binary: str, probefile: str, inputfile: str):
        self.binary = binary
        self.probefile = probefile
        self.inputfile = inputfile

    def getProbes(self) -> list:
        probes = list()
        with open(self.probefile, 'r') as f:
            # delete extra spaces
            f_probes = f.read().split(',')
            probes = [probe.strip() for probe in f_probes]
        return probes

    def getInputs(self) -> list:
        inputs = list()
        with open(self.inputfile, 'r', encoding="utf-8") as f:
            inputs = f.read().splitlines()
        return inputs

    def genJson(self, outputfile: str) -> str:
        data = {
            "target": {
                "core": [1],
                "task": [
                    {
                        "dir": ".",
                        "binary": self.binary,
                        "probes": self.getProbes(),
                        "inputs": self.getInputs()
                    }
                ]
            },
            "contender": {}
        }
        # check outputfile is ending with '.json'
        if not outputfile.endswith('.json'):
            outputfile += '.json'
        with open(outputfile, 'w', encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return outputfile
