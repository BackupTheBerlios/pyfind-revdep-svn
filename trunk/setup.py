import sys
import distutils.core
import pyfind_revdep

long_description = """
pyfind_revdep - find broken binary executables and libraries who have
missing shared object libraries.
"""

distutils.core.setup(name = 'pyfind_revdep',
                     version = pyfind_revdep.__version__,
                     description = 'broken lib/binaries search',
                     long_description = long_description,
                     author = 'LukenShiro',
                     author_email = 'lukenshiro@ngi.it',
                     license = 'GPLv3',
                     platforms = 'POSIX',
                     keywords = 'reverse dependencies',
                     url = 'https://developer.berlios.de/projects/pyfind-revdep/',
                     scripts=['pyfind_revdep'],
                     py_modules=['pyfind_revdep'],
                     data_files=[('doc/pyfind_revdep-'+pyfind_revdep.__version__, \
                                  ['doc/ChangeLog', \
                                  'doc/gpl.txt', 'doc/INSTALL', \
                                  'doc/README', 'doc/TODO'])],
                     )

