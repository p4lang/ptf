"""
Eth platform

This platform uses the --interface command line option to choose the ethernet interfaces.
"""

def platform_config_update(config):
    """
    Update configuration for the local platform

    @param config The configuration dictionary to use/update
    """

    port_map = {}

    for (ofport, interface) in config["interfaces"]:
        port_map[ofport] = interface

    # Default to a veth configuration compatible with the reference switch
    if not port_map:
        max_port_cnt = 288
        port_count = 9
        device_id = 0
        print "eth.py: device id is ", device_id
        base_if_index = 1
        base_if_index = base_if_index + (2*port_count*device_id)
        base_of_port = device_id*max_port_cnt
        for idx in range(port_count):
            port_map[base_of_port + idx] = "veth%d" % (base_if_index + 2 * idx)
    config['port_map'] = port_map
