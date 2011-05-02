#!/bin/bash
#
# Copyright 2011 Google Inc. All Rights Reserved.
# Author: watson@google.com (Tony Watson)

rev=`svn up|awk '{print $3}'`
archive="capirca-r"$rev"tgz"
filedir='./capirca'

echo "Building: $archive"
find . -name \*.pyc -exec rm {} \;
pushd . > /dev/null
cd ..
tar -czf $archive --exclude-vcs $filedir
mv $archive $filedir
popd > /dev/null
ls -al $archive
echo "Done."

