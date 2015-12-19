#!/usr/bin/env python3

import os
import sys
from distutils.core import setup

if sys.version_info < (3, 4, 0):
    sys.stderr.write("This script requires Python 3.4 or newer.")
    sys.stderr.write(os.linesep)
    sys.exit(-1)


setup(
    name='mammon',
    packages=[
        'mammon',
        'mammon.core',
        'mammon.core.ircv3',
        'mammon.core.rfc1459',
        'mammon.ext',
        'mammon.ext.ircv3',
        'mammon.ext.rfc1459',
        ],
    )

# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
