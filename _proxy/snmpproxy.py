# -*- coding: utf-8 -*-

import logging
import traceback
import salt.utils.platform

# Attempt to import the necessary external packages
try:
    from pysnmp.hlapi import *
    from pysnmp.smi import builder
    from pysnmp.smi import view
    from pysnmp.proto import rfc1902
    HAS_SNMP = True
except ImportError:
    HAS_SNMP = False

log = logging.getLogger(__file__)
__proxyenabled__ = 'snmp'
TARGET = {}

'''
Virtual function
'''
def __virtual__():
    log.debug("INIT STAGE 1")
    log.debug(f"HAS_SNMP: {HAS_SNMP}")
    if salt.utils.platform.is_proxy() and HAS_SNMP:
        log.debug('INIT STAGE 2: Returning True')
        return True
    else:
        log.debug('INIT STAGE 2: Returning False')
        return (False, 'Please install pysnmp library: `pip install pysnmp pysnmp-mibs`')


def init(opts):
    log.debug('INIT STAGE 3')
    context = opts.get('proxy', {})         # Load the proxy pillar to get the connection context
    print(context)
    # Build the configuration dictionary
    TARGET['config'] = {
        'target': context.get('target'),
        'version': context.get('version') or 2, 
        'port': context.get('port') or ('UDP', 161),
        'auth_user': context.get('auth_user') or None,
        'auth_key': context.get('auth_key') or None,
        'auth_type': context.get('auth_type') or None,
        'priv_key': context.get('priv_key') or None,
        'priv_type': context.get('priv_type') or None,
        'community': context.get('community') or 'public',
        'context': context.get('context') or None
    }

    # Build the runtime dictionary containing the SNMP objects
    TARGET ['runtime'] = {
        'snmpEngine': SnmpEngine(),
        'transportTarget': UdpTransportTarget((TARGET['config']['target'], TARGET['config']['port'][1])),
    }

    # Runtime objects will differ based on the SNMP version used. Setup those values below
    if TARGET['config']['context']:
        TARGET['runtime']['contextData'] = ContextData(contextName=TARGET['config']['context'])
    else:
        # Setup with default context
        TARGET['runtime']['contextData'] = ContextData()

    if TARGET['config']['version'] == 3:
        auth_type = usmNoAuthProtocol       # Default to no auth
        if TARGET['config']['auth_type'].upper() == 'MD5':
            auth_type = usmHMACMD5AuthProtocol 
        elif TARGET['config']['auth_type'].upper() == 'SHA':
            auth_type = usmHMACSHAAuthProtocol
        elif TARGET['config']['auth_type'].upper() == 'SHA-128':
            auth_type = usmHMAC128SHA224AuthProtocol
        elif TARGET['config']['auth_type'].upper() == 'SHA-192':
            auth_type = usmHMAC192SHA256AuthProtocol
        elif TARGET['config']['auth_type'].upper() == 'SHA-256':
            auth_type = usmHMAC256SHA384AuthProtocol

        priv_type = usmNoPrivProtocol
        if TARGET['config']['priv_type'].upper() == 'DES':
            priv_type = usmDESPrivProtocol 
        elif TARGET['config']['priv_type'].upper() == '3DES':
            priv_type = usm3DESEDEPrivProtocol
        elif TARGET['config']['priv_type'].upper() == 'AES-128':
            priv_type = usmAesCfb128Protocol
        elif TARGET['config']['priv_type'].upper() == 'AES-192':
            priv_type = usmAesCfb192Protocol
        elif TARGET['config']['priv_type'].upper() == 'AES-256':
            priv_type = usmAesCfb256Protocol

        TARGET['runtime']['authData'] = UsmUserData(
            userName=TARGET['config']['auth_user'],
            authKey=TARGET['config']['auth_key'],
            privKey=TARGET['config']['priv_key'],
            authProtocol=auth_type,
            privProtocol=priv_type,
        )

    else:
        # If version is < 3 then we need to setup the community
        if TARGET['config']['community']:
            if TARGET['config']['version'] == 1:
                mp_model = 0
            else:
                mp_model = 1 # Default to SNMPv2

        TARGET['runtime']['authData'] = CommunityData(TARGET['config']['community'], mpModel=mp_model)

    mib_builder = builder.MibBuilder()
    # Add custom mib sources
    for source in opts.get('load_mibs', []):
        mib_builder.addMibSources(builder.DirMibSource(source))
        log.debug(f"Loaded MIB module {source}")

    print(mib_builder.getMibSources())
    mib_builder.loadModules('SNMPv2-MIB')
    TARGET['mib'] = view.MibViewController(mib_builder)

    if ping():
        TARGET['initialised'] = True
    else:
        TARGET['initialised'] = False


def ping():
    # ping = query([('SNMPv2-MIB', 'sysDescr', 0)])
    ping = query([('SNMPv2-MIB', 'sysDescr', 0)])
    print(ping)
    if not ping['success']:
        # Check the error if its connection related, return false
        return False
    return True


def initialized():
    return TARGET['runtime']['initialised']


def shutdown():
    return True


def alive(opts):
    pass


def grains():
    pass


def query(object_list: list, method: str = 'GET') -> list:
    if method.upper() == 'GET':
        iter = getCmd(**TARGET['runtime'])
    elif method.upper() == 'SET':
        iter = setCmd(**TARGET['runtime'])
    elif method.upper() == 'NEXT':
        iter = nextCmd(**TARGET['runtime'])
    elif method.upper() == 'BULK':
        iter = bulkCmd(**TARGET['runtime'])
    else:
        raise

    next(iter)

    return_values = {'success': False, 'output': {}} # Lets assume it didn't work

    while object_list:
        oid = object_list.pop()
        if type(oid) == tuple:
            obj = [ObjectType(ObjectIdentity(*oid).resolveWithMib(TARGET['mib']))]
        else:
            obj = [ObjectType(ObjectIdentity(oid).resolveWithMib(TARGET['mib']))]

        print(obj)
        errorIndication, errorStatus, errorIndex, varBinds = iter.send(obj)
        print(errorIndication, errorStatus, errorIndex)
        if errorIndication:
            return_values['error'] = str(errorIndication) + ' at ' + str(errorIndex)
        elif errorStatus:
            return_values['error'] = errorStatus.prettyPrint()
        else:
            return_values['success'] = True
            for varBind in varBinds:
                ret_val = str(varBind[1])
                if isinstance(varBind[1], rfc1902.Gauge32):
                    ret_val = int(varBind[1])

                return_values['output'][varBind[0].prettyPrint()] = ret_val

    return return_values
