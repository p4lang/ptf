"""A pluggable packet module

This module dynamically imports definitions from packet manipulation module,
specified in config or provided as an argument.
The default one is Scapy, but one can develop its own packet manipulation framework and
then, create an implementation of packet module for it (for Scapy it is packet_scapy.py)
"""

from ptf import config

# When module ptf.packet is imported, this is the order of precedence for
# deciding which packet manipulation module is used:
# (1) If the key "packet_manipulation_module" is present in dict
#     'config', then its value should be a string, and it will be used
#     as the name of the module to use.
# (2) Otherwise, if the environment variable
#     PTF_PACKET_MANIPULATION_MODULE is defined, use its value.
# (3) Otherwise, the default module name "ptf.packet_scapy" is used.

# Note: Applications using ptf.packet can control the choice of packet
# manipulation module in any way they wish by doing the following:
#
# import ptf
# ptf.config["packet_manipulation_module"] = my_app_choice_of_pmm
# import ptf.packet

if "packet_manipulation_module" in config:
    _packet_manipulation_module = config["packet_manipulation_module"]
else:
    import os

    env_val = os.getenv("PTF_PACKET_MANIPULATION_MODULE")
    if env_val:
        _packet_manipulation_module = env_val
    else:
        _packet_manipulation_module = "ptf.packet_scapy"

__module = __import__(_packet_manipulation_module, fromlist=["*"])
__keys = []

# import logic - everything from __all__ if provided, otherwise
# everything not starting with underscore.
print("Using packet manipulation module: %s" % __module.__name__)
if "__all__" in __module.__dict__:
    __keys = __module.__dict__["__all__"]
else:
    __keys = [k for k in __module.__dict__ if not k.startswith("_")]

locals().update({k: getattr(__module, k) for k in __keys})
