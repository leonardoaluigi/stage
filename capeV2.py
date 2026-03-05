import requests
import json
import time
from graphviz import Digraph
import subprocess


url_create_file = 'http://localhost:8000/apiv2/tasks/create/file/'
headers = {'Authorization' : 'Token d256567a66cc7cb3f903389f873277b5a1fe4bb2'}
SAMPLE_FILE = '/home/leonal/Scaricati/'
dot = Digraph(comment= 'process tree')
nodes_pid = set()#set to check if a node is already in graph


Akira = '06c2a137c31aae5d02b4d7df61ffd31f1af9a9e59978f15b3f7265cc751bff1f.zip'
LockBit = '25fba0e92d00184dde662c7d30aff006851dba296daa6f6f82ce797b66789ed2.zip'
Rhysida = '1a9c27e5be8c58da1c02fc4245a07831d5d431cdd1a91cd35d2dd0ad62da71cd.zip'
MedusaLocker = '1bc0575b3fc6486cb2510dac1ac6ae4889b94a955d3eade53d3ba3a92d133281.zip'
Dharma = 'e9bbcfb5d9f42ef0dd75eb435e78d5226087679593893e0c08977694e720cd7a.zip'

#function to add a principal node
def addNode(process = None):
    if process == None:
        return
    else:
        if not process.get('pid') in nodes_pid:
            label = f'{process.get('name')}\nPID: {process.get('pid')}\nNumber of threads: {len(process.get('threads'))}\nCommandLine: {process.get('environ')['CommandLine']}'
            dot.node(f'{process.get('pid')}', label )
            nodes_pid.add(process.get('pid'))
            for child in process['children']:
                addNodeChildren(child,process)
            return
        else:
            return

#function to add a children node
def addNodeChildren(child = None, parent_process = None):
    if not child.get('pid') in nodes_pid:
        child_label = f'{child.get('name')}\nPID: {child.get('pid')}\nPPID: {parent_process.get('pid')}\nNumber of Threads: {len(child.get('threads'))}\nCommandLine: {child.get('environ')['CommandLine']}'
        dot.node(f'{child.get('pid')}', child_label)
        nodes_pid.add(child.get('pid'))
        dot.edge(f'{parent_process.get('pid')}', f'{child.get('pid')}')
        for c_child in child.get('children'):
            addNodeChildren(c_child, child)
    else:
        return

while True:
    print('Which ransomware do you want to analyze with Cape?')
    print('1. Akira')
    print('2. LockBit')
    print('3. Rhysida')
    print('4. MedusaLocker')
    print('5. Dharma')


    choiche = input('Your choiche:')
    if not choiche.isdigit():
        print('You must insert a numeric value between 1 and 5.')
        continue
    
    choiche = int(choiche)
    if choiche < 1 or choiche > 5:
        print('You must insert a value between 1 and 5')
        continue
    break
    

if choiche == 1:
    SAMPLE_FILE += Akira
elif choiche == 2:
    SAMPLE_FILE += LockBit
elif choiche == 3:
    SAMPLE_FILE += Rhysida
elif choiche == 4:
    SAMPLE_FILE += MedusaLocker
else:
    SAMPLE_FILE += Dharma

try:
#we need 'with' to avoid the use of close() after the read of file opened through open()
    with open(SAMPLE_FILE, 'rb') as sample:
        params = {
            'package' : '',
            'machine' : '',
            'timeout' : 200,
            'options' : 'password=infected',
            'priority' : 2,
            'platform' : '',
            'tags' : '',
            'custom' : '',
            'memory' : '',
            'enforce_timeout' : '',
            'clock' : ''
            }
        multipart_file = {'file' : (SAMPLE_FILE, sample)}
        response = requests.post(url_create_file, headers = headers, files = multipart_file, data = params)
        data = response.json()
        id_task = data['data']['task_ids'][0]
        subprocess.run(['mkdir', f'cape_analysis_{id_task}'], capture_output = True)
        capture = subprocess.Popen(['tcpdump','-i','virbr1','-w',f'/home/leonal/Scrivania/tirocinio/cape_analysis_{id_task}/net_capture'])
        print(id_task)
except requests.RequestException as e:
    print(f'request error: {e}')
    exit(1)
except json.JSONDecodeError as e:
    print(f'Not a valid JSON: {e}')
    exit(1)
except FileNotFoundError as e:
    print(f'{SAMPLE_FILE} do not exist: {e}')
    exit(1)

url_task_status = f'http://localhost:8000/apiv2/tasks/status/{id_task}'


while True:
    try:
        status = requests.get(url_task_status, headers = headers).json()['data']
        print('The status of your task with id:', id_task, 'is ' + status)
        if(status != 'reported'):
            print('Please wait...')
            time.sleep(10)
        else:
            break
    except requests.RequestException as e:
        print(f'Request error : {e}')
        exit(1)
    except json.JSONDecodeError as e:
        print(f'Not valid JSON: {e}')
        exit(1)


print(f'The analysis is finished.\nReports will be downloaded at /home/leonal/Scrivania/tirocinio/cape_analysis_{id_task}')

capture.terminate()

url_get_report = f'http://localhost:8000/apiv2/tasks/get/report/{id_task}'
url_get_iocs = f'http://localhost:8000/apiv2/tasks/get/iocs/{id_task}/detailed'

try:
    response = requests.get(url_get_report, headers = headers)
    report = response.json()
except requests.RequestException as e:
    print(f'Request error : {e}')
    exit(1)
except json.JSONDecodeError as e:
    print(f'Not valid JSON: {e}')
    exit(1)

try:
    response = requests.get(url_get_iocs, headers = headers)
    iocs = response.json()
except requests.RequestException as e:
    print(f'Request error : {e}')
    exit(1)
except json.JSONDecodeError as e:
    print(f'Not valid JSON: {e}')
    exit(1)

for process in report['behavior']['processtree']:
    addNode(process)

dot.render(f'cape_analysis_{id_task}/processtree', view = False)

try:
    with open(f'cape_analysis_{id_task}/cape_report.txt' , 'w') as r:

        r.write('DETECTIONS:\n')
        for detection in report['detections']:
            for detail in detection['details']:
                r.write(f'Cape detected {detection.get('family')} using YARA rule: {detail.get('Yara')}\n')

        r.write('\nDROPPED FILES:\n')
        for i,dropped_file in enumerate(report['dropped'], start = 0):
            r.write(f'NO. {i}:\n')
            r.write(f'Name: {dropped_file.get('name')}\nPath: {dropped_file.get('path')}\n\n')
        
        r.write('SIGNATURES:\n')
        for i,signature in enumerate(report['signatures'], start = 0):
            r.write(f'NO. {i}:\n')
            r.write(f'Name: {signature.get('name')}.\nDescription: {signature.get('description')}\nSeverity level: {signature.get('severity')}\n\n')

        r.write('TTPS:\n')
        for i,ttp in enumerate(report['ttps'], start = 0):
            r.write(f'NO. {i}:\n')
            r.write(f'Signature: {ttp.get('signature')}.\nttps: {ttp.get('ttps')}\n\n')
except Exception as e:
    print(f'Error during report creation: {e}')


try:
    with open(f'cape_analysis_{id_task}/files_report.txt','w') as r:
    
        r.write('MODIFIED:\n\n')
        for mod in iocs['data']['files']['modified']:
            r.write(f'{mod}\n')

        r.write('\n\nDELETED:\n\n')
        for deleted in iocs['data']['files']['deleted']:
            r.write(f'{deleted}\n')

        r.write('\n\nREAD:\n\n')
        for read in iocs['data']['files']['read']:
            r.write(f'{read}\n')
except Exception as e:
    print(f'Error during File report creation: {e}')


try:
    with open(f'cape_analysis_{id_task}/key_registry_report.txt', 'w') as r:
    
        r.write('MODIFIED:\n\n')
        for mod in iocs['data']['registry']['modified']:
            r.write(f'{mod}\n')

        r.write('\n\nDELETED:\n\n')
        for deleted in iocs['data']['registry']['deleted']:
            r.write(f'{deleted}\n')

        r.write('\n\nREAD:\n\n')
        for read in iocs['data']['registry']['read']:
            r.write(f'{read}\n')
except Exception as e:
    print(f'Error during Key Registy report creation: {e}')

        
    
    
                
        
    

























