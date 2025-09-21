import base64
import logging
from typing import cast

INSIDE_LEVEL = 15
OUTSIDE_LEVEL = 21

class StructuredLogger(logging.Logger):
    def inside(self, message, *args, **kwargs):
        if self.isEnabledFor(15):
            safe_args = self._safe_args(args)
            self._log(15, message, safe_args, **kwargs)

    def outside(self, message, *args, **kwargs):
        if self.isEnabledFor(21):
            safe_args = self._safe_args(args)
            self._log(21, message, safe_args, **kwargs)

    @staticmethod
    def _safe_args(args):
        if args is None:
            return ""
        return tuple(
            base64.b64encode(a).decode() if isinstance(a, bytes) else a
            for a in args
        )

def instantiate_logger(name: str) -> StructuredLogger:
    logging.addLevelName(INSIDE_LEVEL, f"{name.upper()}_INSIDE")
    logging.addLevelName(OUTSIDE_LEVEL, f"{name.upper()}_OUTSIDE")

    logging.setLoggerClass(StructuredLogger)
    basic_logger = logging.getLogger(name)
    basic_logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)s | %(message)s')
    handler.setFormatter(formatter)
    basic_logger.addHandler(handler)

    logger = cast(StructuredLogger, basic_logger)
    return logger