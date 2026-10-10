"""Addresses of the AWS testbed hosts, from the environment.

The testbed's shell profile (/etc/profile.d/caliban-testbed.sh, deploy/aws/testbed) exports
GATEWAY_IP, GPU_IP and LOADGEN_IP. ROUTER_IPS (space separated) comes from `tofu output hosts`.
"""
import os
import sys


def ip(name):
    v = os.environ.get(name, "").strip()
    if not v:
        sys.exit(f"set {name} (the testbed profile exports GATEWAY_IP, GPU_IP and LOADGEN_IP; "
                 "ROUTER_IPS is space separated, from `tofu output hosts`)")
    return v


def ips(name):
    return ip(name).split()


def env_default(name, fmt="{}"):
    """argparse default: formatted from the variable if it is set, else None (then required)."""
    v = os.environ.get(name, "").strip()
    return fmt.format(v) if v else None
