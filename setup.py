import os
import site
PROJECT_NAME = 'DNS_Proxy'
with open('./bin/' + PROJECT_NAME + '.pth', 'w') as f:
    f.write(os.getcwd() + '\n')
    f.write(os.getcwd() + '/src\n')
    f.close()
os.system('cp ./bin/' + PROJECT_NAME + '.pth ' + site.getsitepackages()[0])
