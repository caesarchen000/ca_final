libamf: An AMF (Andrew's Markup Format) parser
------

Andrew designed his own markup format as part of the RISC-V ISA spec.  I
couldn't find a usable parser for it, so I just wrote one myself.

While you can build libamf using pconfigure (see
<http://github.com/palmer-dabbelt/pconfigure>), you probably don't want to.
For ease of integration, libamf is just a single header file.  It compiles in
ANSI C and has no dependencies on anything (even the C standard library), so
you should be able to just drop it into anything and have it work.
