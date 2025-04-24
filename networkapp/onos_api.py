import requests

def onos_auth():
    return ('onos', 'rocks')

def get_topology():
    base_url = "http://192.168.43.126:8181/onos/v1"
    devices = requests.get(f"{base_url}/devices", auth=onos_auth()).json()['devices']
    links = requests.get(f"{base_url}/links", auth=onos_auth()).json()['links']
    
    return {
        'devices': devices,
        'links': links
    }

def create_tunnel(json_data):
    url = "http://localhost:8181/onos/v1/tunnels"
    res = requests.post(url, json=json_data, auth=onos_auth())
    return res.status_code