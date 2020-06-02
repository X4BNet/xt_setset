# ipset enhanced modules

## xt_setset

match module that does the job of `-j SET`

match module can be used to bump the timeout (ipset can now be an xt_recent replacement) using the `--ss-exist` flag

Returns on match if `--ss-match` flag provided

## xt_setban

a single rule banning module