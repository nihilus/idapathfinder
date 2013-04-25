#!/usr/bin/env python

import sys
import shutil
import os.path

try:
	ida_dir = sys.argv[1]
except:
	print "Usage: %s <path to IDA install directory>" % sys.argv[0]
	sys.exit(1)

files = [
	os.path.join('python', 'pathfinder.py'),
	os.path.join('plugins', 'idapathfinder.py')
]

if os.path.exists(ida_dir):
	for srcfile in files:
		shutil.copyfile(srcfile, os.path.join(ida_dir, srcfile))
	print "PathFinder installed to '%s'." % ida_dir
else:
	print "Install failed, '%s' does not exist!" % ida_dir
	sys.exit(1)
