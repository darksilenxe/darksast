import hashlib
import pickle
import requests
import subprocess
import yaml
from django.views.decorators.csrf import csrf_exempt

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

# CSRF: disabling Django/Flask-WTF CSRF protections.
@csrf_exempt
def unsafe_view(request):
    return request

CSRF_COOKIE_SECURE = False
WTF_CSRF_ENABLED = False
