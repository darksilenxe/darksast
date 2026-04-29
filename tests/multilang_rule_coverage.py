import hashlib
import pickle
import requests
import subprocess
import yaml

user_input = "whoami"
blob = b"payload"
data = b"secret"
url = "https://example.invalid"

subprocess.run(user_input, shell=True)
eval(user_input)
yaml.load(data)
pickle.loads(blob)
requests.get(url, verify=False)
hashlib.md5(data).hexdigest()
