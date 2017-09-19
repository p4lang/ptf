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

    for (device, port, interface) in config["interfaces"]:
        port_map[(device, port)] = interface

    # Default to a veth configuration compatible with the reference switch
    if not port_map:
        port_map = {
            (0, 0): 'veth1',
            (0, 1): 'veth3',
            (0, 2): 'veth5',
            (0, 3): 'veth7',
            (0, 4): 'veth9',
            (0, 5): 'veth11',
            (0, 6): 'veth13',
            (0, 7): 'veth15',
            (0, 8): 'veth17',
            (0, 9): 'veth19',
            (0, 10): 'veth21',
            (0, 11): 'veth23',
            (0, 12): 'veth25',
            (0, 13): 'veth27',
            (0, 14): 'veth29',
            (0, 15): 'veth31',
            (0, 16): 'veth33',
        }

    config['port_map'] = port_map
