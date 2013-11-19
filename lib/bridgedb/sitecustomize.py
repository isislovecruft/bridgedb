# -*- coding: utf-8 -*-
"""sitecustomize ― Handles potential loading of extra code when Python starts.

**Module Usage:**

This is normally (this seems not to work with Twisted, for as-of-yet unknown
reasons) useful for using :mod:`coverage` to measure code execution in spawned
subprocesses in the following way:

 1. Set the environment variable ``COVERAGE_PROCESS_START`` to the absolute
    path of the coverage config file. If you are in the top-level of the
    bridgedb repo, do:

        $ export COVERAGE_PROCESS_START="${PWD}/.coveragerc"

 2. In that coverage config file, in the ``[run]`` section, set 
    ``parallel = True``.

 3. Run coverage. From the top-level of the bridgedb repo, try doing:

        $ make reinstall && \
            coverage run $(which trial) ./lib/bridgedb/test/test_* && \
            coverage combine && coverage report && coverage html

If ``COVERAGE_PROCESS_START`` is not set, this code does nothing,
``[run] parallel`` should be set to ``False``, and coverage can be run by
leaving out the ``coverage combine`` portion of the above command.

To view the output HTML coverage data, open
``path/to/bridgedb_repo/doc/coverage_html/index.html`` in a browser.
"""

import coverage
coverage.process_startup()
