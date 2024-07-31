class WriteOperationException(Exception):
    pass

class InvalidLTLFormulaException(Exception):
    pass

class NonExistentByte(Exception):
    pass

class NonExistentStackFrame(Exception):
    pass

class NonExistentBufferMap(Exception):
    pass

class FailedConcolicExecution(Exception):
    pass

class FailedLoopUnrolling(Exception):
    pass