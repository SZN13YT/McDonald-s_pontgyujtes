from flask import jsonify
import requests

"""
JELENLEGI ADM JELSZÓ: Kiskacsa2070
"""

base_url = "http://127.0.0.1:5001"

session = requests.Session()
response = session.post(url=f"{base_url}/login", json=({"username": "admin", "password": "admin"}))
print(response.json())
# print(session.cookies.get_dict())

# try:
#     response = session.put(url=f"{base_url}/change-password", json=({"password": "admin", "new_password": "Kiskacsa2070"}), cookies=response.cookies.get_dict() )
#     print(response.json())
# except: print(response.json())  

response = session.post(url=f"{base_url}/logout")
data = response.json()
print(data)

"""try:
    response = session.post(
        url=f"{base_url}/create-user", 
        json={"name": "admin", "username": "admin", "password": "admin", "admin": True},
        cookies=response.cookies.get_dict()
        )
    data = response.json()
    print(data)
    
except: print(response)"""