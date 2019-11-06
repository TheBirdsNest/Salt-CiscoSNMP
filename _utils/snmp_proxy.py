from pysnmp.hlapi import * 


class SnmpLegacyInterface():
    def __init__(self, engine:SnmpEngine, community_data:CommunityData, target:str, port:tuple):
        pass

class SnmpV3Interface():
    pass


class SnmpInterface():
    def __init__(self, engine, c)