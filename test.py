class SegmentFunction:
    SEG_NAME_SEP="__"
    @staticmethod
    def makeSegmentName(funcname: str, segno: str, SEP: str = SEG_NAME_SEP):
        return funcname + SEP + segno


from collections import deque
def parseSegmentName(segname: str):
    sepidx = segname.rfind(SegmentFunction.SEG_NAME_SEP)
    return ("", "") if segname is None else (segname[:sepidx], segname[sepidx+len(SegmentFunction.SEG_NAME_SEP):])

# 假设你的列表是 lst
lst = ['4735694.083614,main__0','4735694.083664,func3__0','4735694.083678,func3__return', '4735694.083651,main__1', '4735694.083855,caseb__return']
# 使用列表推导式进行分割
result = [[part1] + list(parseSegmentName(part2)) for part1, part2 in (s.split(',') for s in lst)]
last_func = deque()
for data in result:
    last_func.append((data[0], data[1], SegmentFunction.makeSegmentName(data[1], data[2]), SegmentFunction.makeSegmentName(data[1], data[2], "")))
    
print(last_func)

last_time, last_funcname, last_segno = 1, 2, "easg"
this_time, this_funcname, this_segno = last_time, last_funcname, last_segno
print(this_time, this_funcname, this_segno)