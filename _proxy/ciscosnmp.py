# -*- coding: utf-8 -*-
'''

'''
import ipaddress

try:
    from pysnmp.hlapi import *
    HAS_SNMP = True
except KeyError:
    HAS_SNMP = False

from salt.utils.snmp import *

def __virtual__():
    pass

def init(opts):
    '''
    Sets up SNMP Engine process and tests accessibility to the device
    '''

    conn_info = opts.get('proxy', {})
    TARGET_DEVICE['CONFIG'] = {}
    TARGET_DEVICE['CONFIG']['TARGET'] = conn_info.get('target')
    TARGET_DEVICE['CONFIG']['VERSION'] = conn_info.get('version') or 2
    TARGET_DEVICE['CONFIG']['PORT'] = conn_info.get('port') or ('UDP', 161)
    TARGET_DEVICE['CONFIG']['SNMP_USER'] = conn_info.get('username') or None
    TARGET_DEVICE['CONFIG']['SNMP_PASSWORD'] = conn_info.get('password') or None
    TARGET_DEVICE['CONFIG']['AUTH_TYPE'] = conn_info.get('auth_type') or None
    TARGET_DEVICE['CONFIG']['AUTH_PROTOCOL'] = conn_info.get('auth_protocol') or None
    TARGET_DEVICE['CONFIG']['COMMUNITY'] = conn_info.get('community') or 'public'
    TARGET_DEVICE['CONFIG']['WRITE_ACCESS'] = conn_info.get('write_access') or False
    TARGET_DEVICE['CONFIG']['CONTEXT'] = conn_info.get('context') or None

    TARGET_DEVICE['OPER'] = {}
    TARGET_DEVICE['OPER']['UP'] = False

    TARGET_DEVICE['RUNTIME'] = {}
    TARGET_DEVICE['RUNTIME']['snmpEngine'] = SnmpEngine()
    TARGET_DEVICE['RUNTIME']['transportTarget'] = udpTransportTarget((TARGET_DEVICE['CONFIG']['TARGET'], TARGET_DEVICE['CONFIG']['PORT'][1]))
    TARGET_DEVICE['RUNTIME']['contextData'] = ContextData()

    if TARGET_DEVICE['CONFIG']['VERSION'] == 3:
        TARGET_DEVICE['CREDENTIALS'] = UsmUserData()



    else:
        if TARGET_DEVICE['CONFIG']['COMMUNITY']:
            if TARGET_DEVICE['CONFIG']['VERSION'] == 1:
                mpModel = 0
                TARGET_DEVICE['OPER']['INTERFACE'] = SnmpV1Caller()
            elif TARGET_DEVICE['CONFIG']['VERSION'] == 2:
                mpModel = 1
                TARGET_DEVICE['OPER']['INTERFACE'] = SnmpV2Caller()
            else:
                pass # TODO: Raise an error
            TARGET_DEVICE['OPER']['COMMUNITY_DATA'] = CommunityData(TARGET_DEVICE['CONFIG']['COMMUNITY'], mpModel=mpModel)


    # Attempt to connect to the SNMP target
    ENGINE = SnmpEngine()


def initialized():
    pass

def shutdown():
    pass

def ping():
    pass

def alive(opts):
    pass

def grains():
    pass

'''
Callable functions
'''

def get_cmd():
    CONTEXT = {'snmpEngine': ENGINE, 'authData': None, 'transportTarget': updTransportTarget

def set_cmd():
    pass

def get_bulk_cmd():
    pass

def get_next_cmd():
    pass

