class FileManagerState(object):
    """  A class representing the state of the filemanager. """

    def __init__(self) -> None:
        self.cwd = None


file_manager_state = FileManagerState()
