"""iosvuln - iOS kernel-driver (kext) vulnerability analysis toolkit.

Pipeline:
    IPSW -> kernelcache -> kernelcache.decompressed -> kext inventory
         -> r2 static analysis -> ElleKit userspace hook observations
         -> ranked findings report
"""

__version__ = "0.1.0"
