
# This file tells Python that this is an honest to goodness package.

from ._version import get_versions
from ._langs import get_langs

__version__ = get_versions()['version']
__langs__ = get_langs()

del get_versions
del get_langs
