import psutil


def get_if_list():
    return sorted(psutil.net_if_addrs().keys())
