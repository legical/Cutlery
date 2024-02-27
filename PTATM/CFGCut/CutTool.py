import angr

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

        return angr_cfg, angr_function

    @staticmethod
    def removeFakeRet(angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast):
        angr_cfg, _ = CFGTool.normalizeCFG(angr_cfg=angr_cfg)
        edges_to_remove = [(u, v) for u, v, data in angr_cfg.graph.edges(
            data=True) if data.get('jumpkind') == 'Ijk_FakeRet']
        angr_cfg.graph.remove_edges_from(edges_to_remove)
        return angr_cfg

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
    
    # 判断是否为用户自己定义的函数，且只被main函数调用
    @staticmethod
    def funcOnlyMainCall(cfg: angr.analyses.cfg.cfg_fast.CFGFast, func: angr.knowledge_plugins.functions.function.Function = None, func_addr: int = None) -> bool:
        if func is None:
            if func_addr is None:
                return False
            func = cfg.functions.function(addr=func_addr)
            
        # Normalize this cfg and func first if not normalized.
        CFGTool.normalizeCFG(angr_cfg=cfg, angr_function=func)

        # 判断是否为用户自定义的普通函数
        if not FunctionTool.funcUserDefine(func):
            return False

        node = cfg.get_any_node(func.addr)
        if node.predecessors is None:
            return False

        # 只被main函数调用
        main_function = cfg.functions.function(name="main")
        if 1 == len(node.predecessors) and node.predecessors[0].function_address == main_function.addr:
            return True

        return False
    
    # 通过函数的基本块地址寻找其Function首地址
    @staticmethod
    def getFunctionAddrByBlockAddr(cfg: angr.analyses.cfg.cfg_fast.CFGFast, block_addr: int) -> int:
        node = cfg.get_any_node(block_addr)
        return node.function_address
    
    # 通过函数的基本块地址、函数名、函数首地址获取其Function对象
    @staticmethod
    def getFunctionObj(cfg: angr.analyses.cfg.cfg_fast.CFGFast, block_addr: int = None, func_name: str = None, func_addr: int = None) -> angr.knowledge_plugins.functions.function.Function:
        if func_name is not None:
            func = cfg.functions.function(name=func_name)
            return func
        elif func_addr is not None:
            func = cfg.functions.function(addr=func_addr)
            return func
        else:
            func_addr = FunctionTool.getFunctionAddrByBlockAddr(cfg, block_addr)
            func = cfg.functions.function(addr=func_addr)
            return func
    
    # 构造不推荐函数地址列表，包括main函数和起、止块所在的函数
    @staticmethod
    def getUnrecommendFuncs(cfg: angr.analyses.cfg.cfg_fast.CFGFast, start_addr: int, end_addr: int) -> set:
        unrecommend_funcs = set()
        main_function = cfg.functions.function(name="main")
        unrecommend_funcs.add(main_function.addr)

        start_func_addr = FunctionTool.getFunctionAddrByBlockAddr(cfg, start_addr)
        end_func_addr = FunctionTool.getFunctionAddrByBlockAddr(cfg, end_addr)        
        unrecommend_funcs.add(start_func_addr)
        unrecommend_funcs.add(end_func_addr)

        return unrecommend_funcs
    
    # 获取函数的最后一个基本块首地址
    @staticmethod
    def getFunctionLastBlockAddr(func: angr.knowledge_plugins.functions.function.Function):
        # 获取函数的终止基本块地址
        if len(func.ret_sites) == 1:
            return func.ret_sites[0].addr
        return None