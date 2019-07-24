import logging


def singleton(cls):
    instances = {}

    def get_instance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return get_instance()


@singleton
class Logger():
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.logger.disabled = False

        # self.file_log = logging.FileHandler(log_filename)
        # self.file_log.setLevel(logging.INFO)

        streamLog = logging.StreamHandler()
        streamLog.setLevel(logging.INFO)

        formatter = logging.Formatter('L:%(lineno)d - %(asctime)s - '
                                      '%(levelname)s - %(message)s')
        # self.file_log.setFormatter(formatter)
        streamLog.setFormatter(formatter)

        # self.bgp_logger.addHandler(file_log)
        self.logger.addHandler(streamLog)
