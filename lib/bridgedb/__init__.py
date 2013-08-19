
# This file tells Python that this is an honest to goodness package.

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
