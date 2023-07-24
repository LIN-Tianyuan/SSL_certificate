import inspect

import logbook

def get_logger(name: str | None = None) -> logbook.Logger:
    if name is None:
        root, child = inspect.getmodule(inspect.stack()[1][0]).__name__.split(".", 1)
        name = root + "." + child.removeprefix("_")
    return logbook.Logger(name)