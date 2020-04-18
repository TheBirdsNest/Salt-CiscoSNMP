from pysnmp.hlapi import *

__virtualname__ = 'device'

def __virtual__():
    return __virtualname__

def hostname():
    return __proxy__['ciscosnmp.call']([[ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))]])

def hostname_raw():
    return __proxy__['ciscosnmp.call']([('SNMPv2-MIB', 'sysDescr', 0)])