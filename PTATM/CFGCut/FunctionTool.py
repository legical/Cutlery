import angr
import random

class CFGTool:    
    # normalize angr cfg and function
    @staticmethod
    def normalizeCFG(angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast = None, angr_function: angr.knowledge_plugins.functions.function.Function = None):
        if angr_cfg is not None:
            if not angr_cfg.normalized:
                angr_cfg.normalize()

        if angr_function is not None:
            if not angr_function.normalized:
                angr_function.normalize()

class FunctionTool:
    # 判断是否为用户自定义的普通函数
    @staticmethod
    def funcUserDefine(angr_function: angr.knowledge_plugins.functions.function.Function) -> bool:
        # Normalize this angr_function first if not normalized.
        CFGTool.normalizeCFG(angr_function=angr_function)

        sys_compiler_funcs = ["_init", "_start", "__do_global_dtors_aux", "frame_dummy", "_fini"]
        if angr_function.is_plt or angr_function.has_unresolved_jumps or angr_function.is_simprocedure or angr_function.is_default_name or angr_function.is_syscall or angr_function.name in sys_compiler_funcs or 0 == angr_function.size:
            return False
        else:
            return True
    
    # 判断函数是否只被main函数调用
    @staticmethod
    def funcOnlyMainCall(cfg: angr.analyses.cfg.cfg_fast.CFGFast, func: angr.knowledge_plugins.functions.function.Function) -> bool:
        # Normalize this cfg and func first if not normalized.
        CFGTool.normalizeCFG(angr_cfg=cfg, angr_function=func)

        if not FunctionTool.funcUserDefine(func):
            return False

        node = cfg.get_any_node(func.addr)

        if node.predecessors is None:
            return False

        if 1 == len(node.predecessors) and node.predecessors[0].name.find("main") != -1:
            return True

        return False

class UniqueRandomSelector:
    def __init__(self, items):
        self.items = items.copy()
        self.selected_items = []

    def get_unique_random_element(self):
        if not self.items:
            # 如果所有元素都已经选择过，随机选择一个
            return random.choice(self.selected_items)

        # 从未选择过的元素中随机选择一个
        selected_item = random.choice(self.items)
        self.items.remove(selected_item)
        self.selected_items.append(selected_item)

        return selected_item
    
# 搜索满足条件的函数的方法
class SearchFunc:
    def __init__(self, cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> None:
        self.cfg = cfg
        self.user_functions = set()
        self.passed = set()
        self.cutfuncs = list()

    # 遍历CFG的函数，返回所有只被main调用一次的函数
    def getUserDefineFuncList(self) -> set:
        # Get all func which only called once by main.
        for func in self.cfg.functions.values():
            if FunctionTool.funcOnlyMainCall(self.cfg, func):
                self.user_functions.add(func)
        
        return self.user_functions
    
    def DFSGetFunc(self, node: angr.knowledge_plugins.cfg.cfg_node.CFGNode):
        if node is None:
            return

        if node.function_address in self.passed:
            return
        
        self.passed.add(node.function_address)

        if node.successors is None:
            return
        
        for successor in node.successors:
            if isinstance(successor, angr.knowledge_plugins.cfg.cfg_node.CFGNode):
                self.DFSGetFunc(successor)
            elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
                if successor.addr == node.function_address:
                    continue
                else:
                    if FunctionTool.funcUserDefine(successor):
                        successorNode = self.cfg.get_any_node(successor.addr)
                        self.DFSGetFunc(successorNode)
            else:
                # Add to unresolved_block.
                continue