import requests
from tkinter.filedialog import askopenfilename

myurl = 'http://127.0.0.1:8000/upload-file'
filename = askopenfilename()
file = {'file': open(filename, 'rb')}

data = requests.post(myurl, files=file)

print(data.text)
