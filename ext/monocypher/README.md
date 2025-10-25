Monocypher
----------

uSECboot uses the monocypher library for its cryptographic functions. The
monocypher library has been patched to add a configuration option to reduce
code size: X25519_NO_UNROLLING. This option can be added as a define to
the compile options.

More information about monocypher can be found at:
[Official site.](https://monocypher.org/)
[Official releases.](https://monocypher.org/download/)