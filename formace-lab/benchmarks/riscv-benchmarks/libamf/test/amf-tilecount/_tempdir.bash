tempdir=`mktemp -d -t pcad-memory_complier-tests.XXXXXXXXXX`
trap "rm -rf $tempdir" EXIT

set -ex
cd $tempdir
