$PTEST_BINARY "$LOOKUP_STRING" < config_string > output

diff -u output.gold output
