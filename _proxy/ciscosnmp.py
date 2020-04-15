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
    TARGET_DEVICE['CONFIG']['AUTH_USER'] = conn_info.get('auth_user') or None
    TARGET_DEVICE['CONFIG']['AUTH_KEY'] = conn_info.get('auth_key') or None
    TARGET_DEVICE['CONFIG']['PRIV_KEY'] = conn_info.get('priv_key') or None
    TARGET_DEVICE['CONFIG']['AUTH_TYPE'] = conn_info.get('auth_type') or None
    TARGET_DEVICE['CONFIG']['PRIV_TYPE'] = conn_info.get('priv_type') or None
    TARGET_DEVICE['CONFIG']['COMMUNITY'] = conn_info.get('community') or 'public'
    TARGET_DEVICE['CONFIG']['WRITE_ACCESS'] = conn_info.get('write_access') or False
    TARGET_DEVICE['CONFIG']['CONTEXT'] = conn_info.get('context') or None

    # Runtime dictionary defines the SNMP Engine context data
    TARGET_DEVICE['RUNTIME'] = {}
    TARGET_DEVICE['RUNTIME']['snmpEngine'] = SnmpEngine()
    TARGET_DEVICE['RUNTIME']['transportTarget'] = UdpTransportTarget((TARGET_DEVICE['CONFIG']['TARGET'], TARGET_DEVICE['CONFIG']['PORT'][1]))

    if TARGET_DEVICE['CONFIG']['CONTEXT']:
        TARGET_DEVICE['RUNTIME']['contextData'] = ContextData(contextName=TARGET_DEVICE['CONFIG']['CONTEXT'])
    else:
        TARGET_DEVICE['RUNTIME']['contextData'] = ContextData()

    if TARGET_DEVICE['CONFIG']['VERSION'] == 3:

        AUTH_TYPE = usmNoAuthProtocol
        if TARGET_DEVICE['CONFIG']['AUTH_TYPE'] == 'md5':
            AUTH_TYPE = usmHMACMD5AuthProtocol 
        elif TARGET_DEVICE['CONFIG']['AUTH_TYPE'] == 'sha':
            AUTH_TYPE = usmHMACSHAAuthProtocol
        elif TARGET_DEVICE['CONFIG']['AUTH_TYPE'] == 'sha-128':
            AUTH_TYPE = usmHMAC128SHA224AuthProtocol
        elif TARGET_DEVICE['CONFIG']['AUTH_TYPE'] == 'sha-192':
            AUTH_TYPE = usmHMAC192SHA256AuthProtocol
        elif TARGET_DEVICE['CONFIG']['AUTH_TYPE'] == 'sha-256':
            AUTH_TYPE = usmHMAC256SHA384AuthProtocol

        PRIV_TYPE = usmNoPrivProtocol
        if TARGET_DEVICE['CONFIG']['PRIV_TYPE'] == 'des':
            PRIV_TYPE = usmDESPrivProtocol 
        elif TARGET_DEVICE['CONFIG']['PRIV_TYPE'] == '3des':
            PRIV_TYPE = usm3DESEDEPrivProtocol
        elif TARGET_DEVICE['CONFIG']['PRIV_TYPE'] == 'aes-128':
            PRIV_TYPE = usmAesCfb128Protocol
        elif TARGET_DEVICE['CONFIG']['PRIV_TYPE'] == 'aes-192':
            PRIV_TYPE = usmAesCfb192Protocol
        elif TARGET_DEVICE['CONFIG']['PRIV_TYPE'] == 'aes-256':
            PRIV_TYPE = usmAesCfb256Protocol


        TARGET_DEVICE['RUNTIME']['authData'] = UsmUserData(
            userName=TARGET_DEVICE['CONFIG']['AUTH_USER'],
            authKey=TARGET_DEVICE['CONFIG']['AUTH_KEY'],
            privKey=TARGET_DEVICE['CONFIG']['PRIV_KEY'],
            authProtocol=AUTH_TYPE,
            privProtocol=PRIV_TYPE,
            )

    else:
        if TARGET_DEVICE['CONFIG']['COMMUNITY']:
            if TARGET_DEVICE['CONFIG']['VERSION'] == 1:
                mpModel = 0
            elif TARGET_DEVICE['CONFIG']['VERSION'] == 2:
                mpModel = 1
            else:
                pass # TODO: Raise an error

            TARGET_DEVICE['RUNTIME']['authData'] = CommunityData(TARGET_DEVICE['CONFIG']['COMMUNITY'], mpModel=mpModel)

    status = call(['1.3.6.1.2.1.1.5'])
    

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

def call(object_list: list, method: str = 'get') -> list:
    objects = object_list

    if method == 'get' or method == 'GET':
        iter = setCmd(**TARGET_DEVICE['RUNTIME'])
    elif method == 'set' or method == 'SET':
        iter = getCmd(**TARGET_DEVICE['RUNTIME'])
    elif method == 'next' or method == 'NEXT':
        iter = nextCmd(**TARGET_DEVICE['RUNTIME'])
    elif method == 'bulk' or method == 'BULK':
        iter = bulKCmd(**TARGET_DEVICE['RUNTIME'])
    else:
        raise

    next(iter)

    return_values = {}

    while objects:
        errorIndication, errorStatus, errorIndex, varBinds = iter.send(objects.pop())
        if errorIndication:
            logger.info(objects)
            return_values['error'] = str(errorIndication) + ' at ' + str(errorIndex)
        elif errorStatus:
            logger.info(objects)
            return_values['error'] = errorStatus.prettyPrint()
        else:
            for varBind in varBinds:
                ret_val = varBind[1]
                if isinstance(varBind[1], rfc1902.Gauge32):
                    ret_val = int(varBind[1])

                return_values[varBind[0].prettyPrint()] =ret_val

    return return_values
