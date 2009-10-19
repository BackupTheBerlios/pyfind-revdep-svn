#!/usr/bin/env python
# -*- coding : iso-8859-1 -*-
"""
    pyfind_revdep - find broken binary executables and libraries who have
    missing shared object libraries.

    Copyright (C) 2009  LukenShiro <lukenshiro@ngi.it>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import stat
import re
import sys
import subprocess
import getopt
import gzip
import pickle

__version__ = "0.5.0"
__bdate__ = "20091019"
#elfmagic = str(0x7f454c46L)      # ELF magic


def fatal_error(msg):
    """ Display fatal error message and exits """
    print msg
    sys.exit(1)


def checkroot():
    """ Verify if this script has been executed as root  """

    if os.getuid() != 0:
        fatal_error("You need root privileges to execute this program!")
    return True


def checkpyvers():
    """ Verify if we are using the correct Python version """

    if sys.version_info < (2, 5, 0) or sys.version_info >= (3, 0, 0):
        fatal_error("This program requires Python version 2.5.0 or"
              "\ngreater. Version 3.x is not supported yet.")
    return True


def isbinaryfile(filename):
    """ Returns True if it is a binary (elf) file, else False """

    fsize = os.path.getsize(filename)
    if fsize < 4:   # it doesn't have an header
        return False
    else:
        handl = open(filename, 'rb')
        header = handl.read(4)
        handl.close()
        valuefnd = header.find("ELF")
        if valuefnd == -1:
            # ELF not found in header
            return False
        else:
            return True


def isexecutable(filename):
    """ Returns True if it is an executable (+x) file, else False """

    statist = os.stat(filename)
    mode = statist[stat.ST_MODE]
    if mode & stat.S_IEXEC:
        return True
    else:
        return False


def get_env_path():
    """ Returns PATH directories -> list """

    raw_path_env_var = os.environ.get("PATH")
    if raw_path_env_var is None:
        fatal_error("Fatal Error: environment variable $PATH "
                "doesn't exist.")
    else:
        list_path = raw_path_env_var.split(":")
        unique_list_path = []
        for aaa in list_path:
            if aaa not in unique_list_path:
                if not os.path.islink(aaa):
                    unique_list_path.append(aaa)
        return unique_list_path


def get_env_ldlib():
    """ Returns LD_LIBRARY_PATH directories -> list """

    raw_ldlib_env_var = os.environ.get("LD_LIBRARY_PATH")
    unique_list_ldlib = []
    if raw_ldlib_env_var:
        # if env var doesn't exist
        list_ldlib = raw_ldlib_env_var.split(":")
        for bbb in list_ldlib:
            if bbb not in unique_list_ldlib:
                unique_list_ldlib.append(bbb)
    return unique_list_ldlib


def getversion():
    """ Print program version """
    
    print "pyfind_revdep", "version:", __version__, __bdate__


def isslackware():
    """ Return True is that's Slackware, else False """

    if os.path.exists("/etc/slackware-version"):
        return True
    else:
        return False


def find_common_files(basedir='.'):
    """ Find files who are located in a particular directory -> list """

    matching = []
    for root, dirs, files in os.walk(basedir):
        for fff in files:
            matching.append(root + '/' + fff)
    return matching


def get_ldd_exec():
    """ Returns directory and filename of ldd command -> str """

    okok = False
    pathlist = get_env_path()
    filepath = ""
    for cmd in pathlist:
        filepath = os.path.join(cmd, "ldd")
        #print cmd, filepath
        if os.path.exists(filepath):
            okok = True
            break
    if okok:
        return filepath
    else:
        raise IOError("Fatal Error: executable 'ldd' cannot be found in " \
                      "$PATH.")

def multi_match_fileext(list_of_extensions_re, operstring):
    """ Return True if any of extensions present in list are matching
        else False
    """

    rtnval = False
    for singext in list_of_extensions_re:
        if re.search(singext, operstring):
            rtnval = True
            break
    return rtnval
        

def multi_found_dir(list_of_dir, operstring):
    """ Return True if any of directories present in list are found 
        else False
    """

    rtnval = False
    for singdir in list_of_dir:
        if operstring.find(singdir) != -1:
            rtnval = True
            break
    return rtnval


def run(args):
    """ Main routine """

    if checkroot():
        if checkpyvers():
            appl = FindRevDep()
            appl.getoptions(args)
            appl.print_broken_binfiles()
            appl.print_broken_libfiles()
            appl.print_package_summary()


class FindRevDep(object):
    """ This class is intended to search and display binaries and libraries
        who have broken libraries as dependencies.
    """

    def __init__(self):
        self.list_packages = []
        self.pkg_install_dir = "/var/log/packages"
        self.ldsoconf = "/etc/ld.so.conf"
        self.logfile = "/var/log/pyfind-revdep.log"
        self.dbpkg = "/var/lib/pkgdb.pck"   #pkgdb.pck
        self.dopredict = self.dologreg = False
        self.slack64_list = "/var/lib/slackpkg/slackware64-filelist.gz"
        self.slack32_list = "/var/lib/slackpkg/slackware-filelist.gz"
        self.patches_list = "/var/lib/slackpkg/patches-filelist.gz"
        self.extra_list = "/var/lib/slackpkg/extra-filelist.gz"
        self.testing_list = "/var/lib/slackpkg/testing-filelist.gz"

    def usage(self):
        """ Print program's available options """
        
        print "pyfind_revdep - utility to search broken dependencies files"
        print "Copyright (C) 2009 LukenShiro <lukenshiro@ngi.it>\n"
        print "Usage:  pyfind_revdep [options]\n"
        print "  -p, --predict  ->    Try a prediction of which package is " \
              "behind broken file(s) (Slackware x86 and x86_64 only)."
        print "  -l, --log      ->    Write list of broken files in a log " \
              "as", self.logfile
        print "  -h, --help     ->    This help file."
        print "  -V, --version  ->    Print version number."

    def option_unknown(self):
        """ if an option is not available """
        
        print "Option not recognized"
        self.usage()
        
    def getoptions(self, cli_args):
        """ Manage options inserted as command line arguments """
        
        try:
            opts, args = getopt.getopt(cli_args, "hVplc", \
                            ["help", "version", "predict", "log", "cachepkg"])
        except getopt.GetoptError, err:
            self.option_unknown()
            sys.exit(2)
        for optionval, waste in opts:
            if optionval == "-V":
                getversion()
                sys.exit(0)
            elif optionval in ("-h", "--help"):
                self.usage()
                sys.exit(0)
            elif optionval in ("-p", "--predict"):
                if isslackware():
                    self.dopredict = True
            elif optionval in ("-l", "--log"):
                self.dologreg = True
            elif optionval in ("-c", "--cachepkg"):
                if isslackware():
                    self.cache_stock_slackfiles()
                    sys.exit(0)
                else:
                    fatal_error("This is not a Slackware distribution, so" \
                                "package prediction will not work.")
            else:
                self.option_unknown()
                sys.exit(2)

    def get_libdir(self):
        """ Returns directories contained in /etc/ld.so.conf
            and LD_LIBRARY_PATH -> list.
        """

        handl = open(self.ldsoconf, "r")
        raw_list_libdir = handl.readlines()
        handl.close()
        raw_list_libdir2 = get_env_ldlib()
        raw_list_libdir.extend(raw_list_libdir2)
        list_libdir = []
        for ccc in raw_list_libdir:
            ccc = ccc.strip()
            if not ccc.startswith("#"):
                if ccc not in list_libdir:
                    if not os.path.islink(ccc):
                        list_libdir.append(ccc)
        return list_libdir

    def find_nomasked_files(self, forbidpattern, basedir='.'):
        """ Find files who do NOT have a particular pattern in their file
            name -> list
        """

        matching = forbidfiles = []
        files = find_common_files(basedir)
        for fff in files:
            for singlpattern in forbidpattern:
                regexpr = re.compile(singlpattern)
                if regexpr.match(fff):
                    forbidfiles.append(fff)
                if fff not in forbidfiles:
                    matching.append(fff)
        return matching

    def find_lib_files(self):
        """ Returns all shared object library files -> list """

        libraries = []
        list_libdir = self.get_libdir()
        for libdir in list_libdir:
            newlib = self.find_nomasked_files(['\.a$', '\.la$', '\.dll$' \
                            '\.tcl$', '\.php$'], libdir)
            for fname in newlib:
                if os.path.exists(fname):
                    if isbinaryfile(fname):
                        if isexecutable(fname):
                            libraries.append(fname)
        return libraries

    def find_bin_files(self):
        """ Returns binary executable files -> list """

        binaries = []
        list_path = get_env_path()
        for bindir in list_path:
            newbin = self.find_nomasked_files(['\.py$', '\.sh$', '.csh$',
                            '\.pl$', '\.pm$', '\.rb$'], bindir)
            for fname in newbin:
                if os.path.exists(fname):
                    if isbinaryfile(fname):
                        if isexecutable(fname):
                            binaries.append(fname)
        return binaries

    def get_ldd_sofiles(self, filename):
        """ Returns standard output of ldd $file -> str """
        binexec = get_ldd_exec()
        raw_output = subprocess.Popen(binexec+" "+filename+" 2>/dev/null", \
                    shell=True, stdout=subprocess.PIPE).communicate()[0]
        output = raw_output.replace(" =>", "")
        output = output.replace("\t","")
        output = output.replace("  ", " ")
        if not output:
        #    raise IOError("Fatal Error: executable 'ldd' cannot be found in "
        #                  "$PATH.")
            return ""
        elif output.find("not a dynamic executable") > -1:
            # it doesn't have .so library dependencies
            return ""
        elif output.find("ldd: warning:") > -1:
            return ""
        return output

    def get_list_sodep(self, filename):
        """ Returns a list of .so dependency files """

        listdep = self.get_ldd_sofiles(filename)
        if not listdep:
            # Not a .so file
            return ""
        list_sodep = []
        raw_list_sodep = listdep.split("\n")
        for aaa in raw_list_sodep:
            if aaa:
                strippedstr = (aaa.strip("\t")).strip(" ")
                stripelem = strippedstr.split(" ")
                list_sodep.append(stripelem)

        list_solibs = []
        for bbb in range(0, len(list_sodep)):
            try:
                wasted = list_sodep[bbb][1]
            except IndexError: # index 1 doesn't exist
                continue
            if (list_sodep[bbb][1]).startswith("(") or \
               (list_sodep[bbb][0]).startswith("/"):
                # e.g. ld-linux-x86-64.so.2, ld-linux.so.2,
                # linux-vdso.so.1, linux-gate.so.1
                continue
            libdep = [list_sodep[bbb][0].strip(), list_sodep[bbb][1].strip()]
            list_solibs.append(libdep)

        #print "list_sodep --> ", list_solibs
        return list_solibs

    def get_list_notfound(self, filename):
        """ Returns 'not found' .so dependency files -> list """

        list_notfound = []
        list_solibs = self.get_list_sodep(filename)
        if not list_solibs:
            # Not a .so file
            return ""
        for ccc in range(0, len(list_solibs)):
            if (list_solibs[ccc][1]).startswith("not"):
                # not found                           
                lackingso = list_solibs[ccc][0]
                if lackingso not in list_notfound:
                    # to prevent same .so repetitions
                    list_notfound.append(lackingso)
        return list_notfound

    def convert_slackpkg_in_dict(self, filehandler):
        """ Convert data from a slackpkg file (slackware, patches, extra,
            testing) into a dict
        """

        fileinpkg = {}
        for rowconten in filehandler:
            newrowcont = rowconten.strip(" \n")
            newrowcont = newrowcont.replace(" ./", "").replace(" ", " /")
            listrowconten = newrowcont.split(" ")
            pkgname = os.path.basename(listrowconten[0].replace(".txz", \
                                        "").replace(".tgz", ""))
            # e.g. bsd-games-2.13-x86_64-9
            listlen = len(listrowconten)
            newlistrow = []
            for rowelem in range(1, listlen):
                #print listrowconten[rowelem]
                if listrowconten[rowelem].endswith("/"):
                    # it's a directory, ignore it
                    continue
                elif multi_found_dir(["/install/", "/etc/", "/usr/doc/", \
                            "/usr/share/", "/usr/info/", "/usr/include/", \
                            "/usr/man/", "/usr/src/", "/var/", \
                            "/lib/modules/"], listrowconten[rowelem]):
                    # ignores: installation, config, doc, data, info, 
                    # man, src, and linux module files
                    continue
                elif multi_match_fileext(["\.png$", "\.dtd$", "\.pc$", \
                            "\.awk$", "\.pl$", "\.py$", "\.pyo$", "\.pyc$", \
                            "\.spec$", "\.pm$", "\.docbook", "\.html$", \
                            "\.gif$", "\.a$", "\.desktop$", "\.php$", \
                            "\.h$", "\.rules$", "\.svgz$", "\.xml$", \
                            "\.xul$", "\.properties$", "\.css$", "\.jpg$", \
                            "\.rdf$", "\.ini$", "\.jar$", "\.wav$", "\.mpg$", \
                            "\.cfg$", "\.la$", "\.gz$", "\.bz2$", "\.cf$", \
                            "\.txt$", "\.js$", "\.xpt$", "\.ix$", "\.bs$", \
                            "\.dat$", "\.rws", "\.alias$", "\.multi$", \
                            "\.conf$", "\.tcl$", "\.msg$", "\.pod$", "\.png$", \
                            "\.rtf$", "\.tiff$", "\.xpm$", "\.def$", "\.sh$", \
                            "\.theme$", "\.htm$", "\.rb$", "\.aff$", \
                            "\.tmpl$", "\.class$"], \
                            listrowconten[rowelem]):
                    # ignores some file with uninteresting extension
                    continue                    
                else:
                    newlistrow.append(listrowconten[rowelem])
            if not newlistrow:
                # package containing no un-ignored files
                continue

            fileinpkg[pkgname] = newlistrow
        return fileinpkg
            
        
    def cache_stock_slackfiles(self):
        """ Cache a list of files available in stock Slackware  """

        if os.path.exists(self.slack64_list):
            gzslakhandl = gzip.open(self.slack64_list)
            dlistslak = self.convert_slackpkg_in_dict(gzslakhandl)
            gzslakhandl.close()
        elif os.path.exists(self.slack32_list):
            gzslakhandl = gzip.open(self.slack64_list)
            dlistslak = self.convert_slackpkg_in_dict(gzslakhandl)
            gzslakhandl.close()
        else:
            fatal_error("Files from slackpkg are not found, you must run slackpkg" \
                        "update before using -c option.")
        if os.path.exists(self.patches_list):
            gzpatchandl = gzip.open(self.patches_list)
            dlistpatc = self.convert_slackpkg_in_dict(gzpatchandl)
            gzpatchandl.close()
        else:
            fatal_error("Files from slackpkg are not found, you must run slackpkg" \
                        "update before using -c option.")            
        if os.path.exists(self.extra_list):
            gzextrhandl = gzip.open(self.extra_list)
            dlistextr = self.convert_slackpkg_in_dict(gzextrhandl)
            gzextrhandl.close()
        else:
            fatal_error("Files from slackpkg are not found, you must run slackpkg" \
                        "update before using -c option.")
        if os.path.exists(self.testing_list):
            gztesthandl = gzip.open(self.testing_list)
            dlisttest = self.convert_slackpkg_in_dict(gztesthandl)
            gztesthandl.close()
        else:
            fatal_error("Files from slackpkg are not found, you must run slackpkg" \
                        "update before using -c option.")
        dlistslak.update(dlistpatc)      
        dlistslak.update(dlistextr)
        dlistslak.update(dlisttest)
        pckfile = open(self.dbpkg, "w")
        pickle.dump(dlistslak, pckfile, protocol=2)
        pckfile.close()

    def load_stock_pkgs(self):
        """ Load packages and their files in memory --> list """

        if os.path.exists(self.dbpkg):
            pckfile = open(self.dbpkg, "r")
            dictpkgfil = pickle.load(pckfile)
            pckfile.close()
            return dictpkgfil
        else:
            fatal_error("Stock package cache file not found, you need to " \
                        "build it using '-c' or '--cachepkg' option.")        

    def find_stock_package(self, missinglib):
        """ Return name of stock slackware package whom missinglib belongs
            to --> str
        """
        
        dictpkgfile = self.load_stock_pkgs()
        for groupkey in dictpkgfile:
            for singvalue in dictpkgfile[groupkey]:
                if singvalue.find(missinglib) != -1:
                    return groupkey
        return None


    def ok_varlogpackages(self):
        """ Returns True if /var/log/packages exists, else False """

        if os.path.isdir(self.pkg_install_dir):
            return True
        else:
            return False

    def find_predicted_packages(self, brokenfile):
        """ Returns possible package name whose file(s) is/are broken,
            else 'unknown'
            FIXME: routine catch only first package (problem if a file
            is contained in 2 or more packages)
        """

        pkginstall = "unknown"
        newbrokenfile = brokenfile[1:]      # no leading slash
        if self.ok_varlogpackages():
            list_installed_pkgs = find_common_files(self.pkg_install_dir)
            for installed in list_installed_pkgs:
                handl = open(installed, "r")
                conten_file = handl.readlines()
                handl.close()
                for filerow in conten_file:
                    valuefnd = filerow.find(newbrokenfile)
                    if valuefnd > -1:
                        pkginstall = installed
                        break
        return pkginstall

    def reset_log(self):
        """ Erase the log file and re-create it"""

        if os.path.exists(self.logfile):
            os.unlink(self.logfile)
        logf = open(self.logfile, "w")
        logf.close()

    def manage_log(self, writcontents):
        """ Manage the log file, and write contents to it """

        logf = open(self.logfile, "a+")
        logf.write(writcontents)
        logf.close()

    def print_broken_binfiles(self):
        """ Print individual messages related to broken binary files """

        if self.dologreg:
            self.reset_log()
        list_binary = self.find_bin_files()
        #list_binary = ['/usr/bin/bash', '/usr/bin/a2ps', '/usr/bin/Editra.py']
        print "State of lacking .so dependencies: binary executables in ",
        for aaa in get_env_path():
            print aaa,
        print "\n"
        for singularfile1 in list_binary:
            listbin = self.get_list_notfound(singularfile1)
            if not listbin:
                continue
            for singbin in listbin:
                if self.dopredict:
                    packfile1 = self.find_stock_package(singbin)
                    if packfile1 is None:
                        packfile1 = self.find_predicted_packages(singularfile1)
                    pkgonlyname1 = os.path.basename(packfile1)
                    self.list_packages.append(pkgonlyname1)
                    linetowrite = "broken %47s  depends on: %15s  package: " \
                                  "%15s" % (singularfile1, singbin, \
                                            pkgonlyname1)
                else:
                    linetowrite = "broken %47s  depends on: %15s" \
                                  % (singularfile1, singbin)
                print linetowrite
                if self.dologreg:
                    self.manage_log(linetowrite)

    def print_broken_libfiles(self):
        """ Print individual messages related to broken library files """

        list_library = self.find_lib_files()
        #list_library = ['/usr/lib/pkcs11-spy.so',
        #                '/usr/lib/libxklavier.so.12',
        #                '/usr/lib/libt1.so.5.1.2']
        print "\n\nState of lacking .so dependencies: shared libraries in ",
        for aaa in self.get_libdir():
            print aaa,
        print "\n"
        for singularfile2 in list_library:
            listlib = self.get_list_notfound(singularfile2)
            if not listlib:
                continue
            for singlib in listlib:
                if self.dopredict:
                    packfile2 = self.find_stock_package(singlib)
                    if packfile2 is None:
                        packfile2 = self.find_predicted_packages(singularfile2)
                    pkgonlyname2 = os.path.basename(packfile2)
                    self.list_packages.append(pkgonlyname2)
                    linetowrite = "broken %47s  depends on: %15s  package: " \
                                  "%15s" % (singularfile2, singlib, \
                                            pkgonlyname2)
                else:
                    linetowrite = "broken %47s  depends on: %15s" \
                                  % (singularfile2, singlib)
                print linetowrite
                if self.dologreg:
                    self.manage_log(linetowrite+"\n")

    def print_package_summary(self):
        """ Print a summary with predicted packages """

        if self.dopredict:
            print "\n\nThese are predictable broken packages found:"
            newlist_pkg = []
            for package in self.list_packages:
                if package == "unknown" or package in newlist_pkg:
                    continue
                else:
                    newlist_pkg.append(package)
                    print package,
            if not newlist_pkg:
                print "\nNo package."
            else:
                print "\n\nFor each package you may have to: " \
                      "*re-build* it (if it's possible and it has to be " \
                      "re-compiled against an existing library), or " \
                      "*install* the missing package who owns the library " \
                      "(if that's it to be missing), or " \
                      "*remove* it (if it is obsolete and and not critical)," \
                      " or *copy/symlink* needed library from existing one " \
                      "(only if library's ABI/API has not been modified.)"


if __name__ == '__main__':
    run(sys.argv[1:])
