class InitError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class DataBaseError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)        

class UserError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)         