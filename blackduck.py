import requests
import ast
from ast import literal_eval
import json
import logging
from logging import FileHandler
from logging import Formatter
import os
import urllib3
from paramiko import SSHClient, AutoAddPolicy
import paramiko
from datetime import date
import xlsxwriter
import time
import shutil
import re
import csv
import subprocess
import glob
from pathlib import Path

#from redminelib import Redmine
#from packages.paramiko.client import SSHClient
urllib3.disable_warnings()

class CallCounted:
    """Decorator to determine number of calls for a method"""

    def __init__(self,method):
        self.method=method
        self.counter=0

    def __call__(self,*args,**kwargs):
        self.counter+=1
        return self.method(*args,**kwargs)



class Excel():
    def __init__(self):
        self.workbook = xlsxwriter.Workbook(CONST.BASE_DIR+os.sep +'results.xlsx')
        self.worksheet = self.workbook.add_worksheet()
        self.row = 0
        self.write_title()


    def close(self):
        self.workbook.close()

    def write_title(self):
        headings = ['Product', 'Family','Area','Suite','Data','Critial#','High#','Medium#','Low#','Risk Level','Total Score','Link']
        self.write_row( headings)

    def add_to_row(self,product, family,area,suite,data,critial,high,medium,low,risk_level,total_score,link):
        list =[]
        for item in (product, family,area,suite,data,critial,high,medium,low,risk_level,total_score,link):
            list.append(item)
        return list

    def write_row(self, row):
        col = 0
        for item in row:
            self.worksheet.write(self.row, col, item)
            col = col + 1
        self.row = self.row + 1




class CONST():
    SSH_HOST = '10.209.27.114'
    SSH_USER = 'root'
    SSH_PASS = '3tango'
    BASE_REPO_PATH = '/tmp/'
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_DIR = BASE_DIR + os.sep + 'log' + os.sep
    JSON_DIR = BASE_DIR + os.sep + 'json' + os.sep
    COV_DIR = BASE_DIR + os.sep + 'coverity' + os.sep
    COV_FILE_TEMPLATE = COV_DIR + 'checker_p<>.txt'
    FAMILY = {'HOST FW':['ConnectX FW','Mellanox FW'],
              'MLNX_OS':['MLNX_OS'],
              'WINDOWS':['Windows_Drivers','Windows'],
              'MGMT TOOLS':['OPENSM','NEO','UFM','OpenSM'],
              'LINUX DRIVERS':['MLNX_OFED'],}
    SCORE_CRITICAL = 90
    SCORE_HIGH = 70
    SCORE_MEDIUM = 50
    SCORE_LOW = 0
    MLNX_OS_FILE = '/auto/sysgwork/G/blackduck_automation/branch_scan/'
    CRITICAL_WEIGHT = 1,
    HIGH_WEIGHT = 5,
    MEDIUM_WEIGHT = 10,
    LOW_WEIGHT = 50,



class BD():
    def __init__(self,excel):
        self.bd_mapper = {'ConnectX FW': 'golan_fw',
                          'MLNX_OS':'mlnxos_3_8_2100_rpms_last_ga',
                          'Windows':'WinOF',
                          'OPENSM':'opensm',
                          'NEO':'NEO',
                          'MLNX_OFED':'MOFED_AUTOMATION',
                          'UFM':'UFM'}
        self.excel = excel
        self.aSeasion= requests.Session()
        self.logger = BD.create_logger('blackduck.log')
        self.ssh = SSH(self.logger, CONST.SSH_HOST, CONST.SSH_USER, CONST.SSH_PASS)
        self.logger.error = CallCounted(self.logger.error)
        self.results = {}
        self.links = []
        self.username = 'arielwe'
        self.password = '12345678'
        self.urlbase = 'https://blackduck.mellanox.com/'
        self.authenticate()
        self.collect_data()
        self.overallRiskAggregate = None
        self.projectRiskProfilePageView = None
        self.logger.info('Done with BlackDone')
        print('Done with BlackDuck. errors : ' + str(self.logger.error.counter))


    def dump_results_to_json(self,dict,path):
        self.logger.debug('dumping dictionary into file ' + str(path))
        if not os.path.exists(CONST.JSON_DIR):
            os.mkdir(CONST.JSON_DIR)
        try:
            with open(path, 'w') as fp:
                json.dump(dict, fp)
        except Exception as e:
            self.logger.error('Exception while writing json to file')
        self.logger.debug('Writing to JSON file successded')


    def collect_data(self):
        self.logger.info('Start Collecting data from Blackduck Server')
        self.get_allProjects()

    def get_allProjects(self):
        self.logger.debug('start get all Projects function')
        try:
            url = 'https://blackduck.mellanox.com/api/projects?limit=150'
            #TODO- debug
            url = 'https://blackduck.mellanox.com/api/risk-profile-dashboard?limit=150'
            self.logger.info('Send request to retrive all BD Project')
            res = self.aSeasion.get(url, verify=False)
        except Exception as e:
            self.logger.error('Exception received in get_allProjects')

        if res.status_code == 200:
            self.logger.info('Getting all projects ended with status code 200! ')
            self.parse_project_data(res.content)
            self.create_results()
            self.dump_results_to_json(self.overallRiskAggregate, CONST.JSON_DIR + 'overallRiskAggregate.json')
            self.dump_results_to_json(self.projectRiskProfilePageView,  CONST.JSON_DIR + 'projectRiskProfilePageView.json')
        else:
            self.logger.error('Getting all projects has ended with status code ' + str(res.status_code))

    def get_data_mlnx_os(self):
        self.logger.debug('Start fetching data from mellanox os csv file')
        try:
           output = os.listdir(CONST.MLNX_OS_FILE)
           for file in output:
               if 'all_cves' in file:
                   file_path = CONST.MLNX_OS_FILE + file
                   self.logger.debug('Found CSV file for MLNX_OS : ' + file_path)
                   break
           else:
               self.logger.error('Couldn\'t find csv file for nlmx_os with given regex')
               return None

           try:
               self.logger.debug('Copy CSV file to current directory')
               filename = os.path.dirname(os.path.abspath(__file__))+os.sep + file
               if not os.path.exists(filename):
                   shutil.copyfile(file_path,filename)
               self.logger.debug('Copy file ended successfully')
           except Exception as e:
               self.logger.error('Exception in copy csv file ' + str(e))
                
           dict = BD.create_dict_from_csv(self.logger,filename)

           self.logger.info('Searching for specific Redemtion Status')
           status =['REMEDIATION_REQUIRED','VULNERABLE']
           critical,high,medium,low = 0,0,0,0
           for counter, st in enumerate(dict['Remediation status']):
               if st in status:
                   base_score = dict['Base score'][counter]
                   self.logger.debug('found bug with status ' + str(st) +' with base score ' + base_score)
                   if float(base_score) >= 9:
                       critical +=1
                   elif float(base_score) >=7:
                       high +=1
                   elif float(base_score) >=4:
                       medium+=1
                   else:
                       low+=1

           version_list=[]

           dic = {}
           dic['countType'] = 'CRITICAL'
           dic['count'] = critical
           version_list.append(dic)

           dic = {}
           dic['countType'] = 'HIGH'
           dic['count'] = high
           version_list.append(dic)

           dic = {}
           dic['countType'] = 'MEDIUM'
           dic['count'] = medium
           version_list.append(dic)

           dic = {}
           dic['countType'] = 'LOW'
           dic['count'] = low
           version_list.append(dic)

           dic = {}
           dic['countType'] = 'OK'
           dic['count'] = 0
           version_list.append(dic)

           dic = {}
           dic['countType'] = 'UNKNOWN'
           dic['count'] = 0
           version_list.append(dic)

           return version_list

        except Exception as e:
            self.logger.error('Exception in get data_mlnx_os function' + str(e))
            return None

    @staticmethod
    def create_dict_from_csv(logger,filename):
        logger.info('Reading csv file for mellanox OS')
        try:
            reader = csv.reader(open(filename, 'r'))
            d = {}
            for counter, row in enumerate(reader):
                if counter == 0:
                    for item in row:
                        d[item] = []
                else:
                    for item,key in zip(row,d.keys()):
                        d[key].append(item)

        except Exception as e:
            logger.error('Exception during create dict from csv file' + str(e))
            return None

        logger.info('Creating dictionary from csv file has eneded completely')
        return d
        
    def create_results(self):
        self.logger.debug('Start to create Results object')

        for project,bd_project_name in self.bd_mapper.items():
            self.logger.debug('Searching vulnerabilites for project :' + str(project))
            if project == 'MLNX_OS':
                self.logger.debug('fetching data from csv file for MLNX_OS project')
                version_dict =self.get_data_mlnx_os()
                self.results[project] = version_dict
                self.links.append('No link Available')

            if project != 'MLNX_OS':
                for i in range(len(self.projectRiskProfilePageView['items'])):
                    if self.projectRiskProfilePageView['items'][i]['name'] == bd_project_name:
                        id = self.projectRiskProfilePageView['items'][i]['id']
                        self.logger.debug('version of project is ' + id)
                        version_dict = self.get_last_version(id)
                        self.logger.debug('Found blackduck project on projectRiskProfilePageView Object for project : '  + project)
                        self.results[project] = version_dict
                        self.logger.info('vulerbilities data was added successfully to project ' + project )
                        break;

                else:
                    self.logger.critical('Couldn\'t find project on projectRiskProfilePageView Object for project : '  + project)
                    self.results[project]=None

        self.logger.debug('finish create Result Object')
        self.write_results_to_csv()

    def write_results_to_csv(self,):
        self.logger.info('Writing BD results to CSV')
        counter = 0
        try:
            for product_name, vuln_lst in self.results.items():
                #['Product', 'Family','Area','Suite','Data','Critial#','High#','Medium#','Low#','Total Score']
                family = BD.get_family(self.logger,product_name)
                critial = vuln_lst[0]['count']
                high = vuln_lst[1]['count']
                medium = vuln_lst[2]['count']
                low = vuln_lst[3]['count']
                link = self.links[counter]
                today = date.today()
                date_ = d2 = today.strftime("%B %d, %Y")
                total,level = BD.calculate_total_score(self.logger,product_name,critial,high,medium,low, 'BD')
                row = self.excel.add_to_row(product_name, family,'CVEs','Blackduck',date_, critial,high,medium,low,level,total,link)
                self.excel.write_row(row)
                counter = counter + 1
        except Exception as e:
            self.logger.error('Exception during write results to csv of BD ' + str(e))
        self.logger.debug('finish writing results from BD to CSV')


    @staticmethod
    def calculate_total_score(logger, product_name,critial,high,medium,low,suite):
        logger.debug('Calculating total score')
        level = None
        if critial > 0:
            level = 'CRITICAL'
            total = CONST.SCORE_CRITICAL + int(critial) / CONST.CRITICAL_WEIGHT[0]
            if total > 100:
                total = 100
        elif high > 0:
            level = 'HIGH'
            total = CONST.SCORE_HIGH +int(high) / CONST.HIGH_WEIGHT[0]
            if total > CONST.SCORE_CRITICAL:
                total = CONST.SCORE_CRITICAL
        elif medium > 0:
            level = 'MEDIUM'
            total = CONST.SCORE_MEDIUM + int(medium) / CONST.MEDIUM_WEIGHT[0]
            if total > CONST.SCORE_HIGH:
                total = CONST.SCORE_HIGH
        elif low > 0:
            level = 'LOW'
            total = CONST.SCORE_LOW + int(low) / CONST.LOW_WEIGHT[0]
            if total > CONST.SCORE_MEDIUM:
                total = CONST.SCORE_MEDIUM
        else:
            level = 'LOW'
            total = 0
        logger.info('Total Grade for ' + product_name + ' for' + suite +' is ' + str(total))

        new_total = 100 - total
        return new_total,level

    @staticmethod
    def get_family(logger, product_name):
        logger.debug('Trying to fetch Family name for product')
        for fam, project_lst in CONST.FAMILY.items():
            if product_name in project_lst:
                logger.debug('Product Family found for ' + product_name + ' = '+ fam)
                return fam
                break
        else:
            logger.error('product family was not found in Family dictionary')
            return None

    def get_last_version(self,id):
        self.logger.debug('Start get version')
        url = 'https://blackduck.mellanox.com/api/projects/'+ id +'/versions'
        response = self.aSeasion.get(url,verify=False )
        if response.status_code == 200:
            self.logger.debug('get all version for projects ended succussfully')
            data = json.loads(response.content)
            version_dict = self.compare_versions(data)
            return  version_dict
        else:
            self.logger.error('couldn\'t get versions for project ' + id)

    def compare_versions(self, data):
        self.logger.debug('Start Compare versions')
        if len(data['items']) <= 1:
            self.logger.debug('Only one version has found for project')
            link = data['items'][0]['_meta']['href']
            self.links.append(link)
            self.logger.debug('adding link of version for link array ' + str(link))
            return data['items'][0]['securityRiskProfile']['counts']
        else:
            try:
                num_of_versions = len(data['items'])
                self.logger.debug('Project has ' + str(num_of_versions) + 'versions, checking who is most up to date')
                biggest = data['items'][0]['createdAt']
                index = 0
                for i in range(int(num_of_versions)):
                    if data['items'][i]['createdAt'] > biggest:
                        biggest = data['items'][i]['createdAt']
                        index = i
                self.logger.debug('biggest version was found in index ' + str(index) + ' at time ' + str(biggest))
                link = data['items'][i]['_meta']['href']
                self.links.append(link)
                self.logger.debug('adding link of version for link array ' + str(link))
                return data['items'][index]['securityRiskProfile']['counts']
            except Exception as e:
                self.logger.error('Exception received during compare versions ' + str(e))
                return None

    def bytes_to_json(self, bytes_array):
        self.logger.debug('Change bytes array into JSON')
        try:
            data = json.loads(bytes_array)
        except Exception as e:
            self.logger.error('Exception appear in Converting bytes to JSON' + str(e))
            return None
        return data

    def parse_project_data(self, bytes_content):
        project_dict = self.bytes_to_json(bytes_content)
        self.overallRiskAggregate = project_dict['overallRiskAggregate']
        self.projectRiskProfilePageView = project_dict['projectRiskProfilePageView']

    @staticmethod
    def create_logger(filename):
        LOG_FORMAT = (
            "%(asctime)s [%(levelname)s]: %(message)s ")
        # payments logger
        filename = CONST.LOG_DIR + filename
        if os.path.isfile(filename):
            os.remove(filename)
        logger = logging.getLogger("wasted_meerkats.payments")
        LOG_LEVEL = logging.DEBUG
        logger.setLevel(LOG_LEVEL)
        blackduck_file_handler = FileHandler(filename)
        blackduck_file_handler.setLevel(LOG_LEVEL)
        blackduck_file_handler.setFormatter(Formatter(LOG_FORMAT))
        logger.addHandler(blackduck_file_handler)
        return  logger


    def authenticate(self):
        # Username and password will be sent in body of post request
        self.logger.info('Authinticate Blackduck with username and password')
        data = {
            'j_username': 'arielwe',
            'j_password': '12345678'
        }

        try:
            response = self.aSeasion.post('https://blackduck.mellanox.com/j_spring_security_check', data=data, verify=False)
        except Exception as e:
            self.logger.error('Exception received on authenticated with blackduck')
        # check for Success
        if response.ok:

            self.csrf = response.headers['x-csrf-token']
            self.aSeasion.headers.update({'X-CSRF-TOKEN': self.csrf})
            self.logger.info('Authentication for Blackduck Server is completed successfully')
            self.logger.debug('csrf-token is : ' + self.csrf)
            return 1
        else:
            self.logger.error('Authentication for blackduck server failed. status code is ' + str(response.status_code))
            "Error in authentication to hub server"
            return 0


def create_main_logs():
    LOG_FORMAT = (
        "%(asctime)s [%(levelname)s]: %(message)s in %(pathname)s:%(lineno)d")
    LOG_LEVEL = logging.INFO

    dashboard_log = CONST.LOG_DIR + 'dashboard.log'

    main_logger = logging.getLogger("wasted_meerkats.messaging")
    main_logger.setLevel(LOG_LEVEL)
    main_logger_file_handler = FileHandler(dashboard_log)
    main_logger_file_handler.setLevel(LOG_LEVEL)
    main_logger_file_handler.setFormatter(Formatter(LOG_FORMAT))
    main_logger.addHandler(main_logger_file_handler)
    return  main_logger

class Bandit():
    def __init__(self,excel):
        self.logger = BD.create_logger('bandit.log')
        self.ssh = SSH(self.logger,CONST.SSH_HOST,CONST.SSH_USER,CONST.SSH_PASS)
        self.repos = {'UFM': 'ssh://ibrahimbar@l-gerrit.mtl.labs.mlnx:29418/ufm/gvvm',
                      'NEO':'http://10.7.77.140:8080/dcs/netservices -b master'}
        self.logger.error = CallCounted(self.logger.error)
        self.results ={}
        self.start(excel)
        self.logger.info('Done with Bandit')
        print('Done with Bandit. errors: ' + str(self.logger.error.counter))

    def print_results_to_csv(self,excel):
        try:
            for project in self.repos.keys():
                family = BD.get_family(self.logger, project)
                today = date.today()
                date_ = d2 = today.strftime("%B %d, %Y")
                arr_res = self.results[project]
                critical, high,medium,low = int(arr_res[2]), int(arr_res[1]), int(arr_res[0]), 0
                self.total,level = BD.calculate_total_score(self.logger, project, critical, high, medium, low, 'Bandit')
                row = excel.add_to_row(project, family, 'Static Code Analysis', 'Bandit', date_, critical, high, medium, low,level, self.total, 'No link Available')
                excel.write_row(row)
        except Exception as e:
            self.logger.error('Exception during print_results_to_csv ' + str(e))

    def start(self,excel):
        for project,url in self.repos.items():
            path = self.clone_repository(url,project)
            self.scan(path,project)
            self.print_results_to_csv(excel)

    def scan(self,path,project):
        self.logger.info('Running scan for ' + project  + 'This might take 15-45 minutes')
        cmd = 'bandit -r -a vuln ' + path + '  | grep \'Total issues (by severity)\' -A 4'
        try:
            output = self.ssh.run_command(cmd)
            res = self.parse_output(output)
            self.results[project] = res
        except Exception as e:
            self.logger.error('Exection appears in scan function')

    def parse_output(self,output):
        self.logger.debug('Start Parsing output from command')
        array =['Low','Medium','High']
        res = [ ]
        out_str = '\n'.join(output)
        try:
            for sev in array:
                reg = sev+':'+' (\d*)'
                x =re.findall(reg,out_str)[0]
                if x:
                    self.logger.debug('found ' + str(x) + ' vulnerabilities in severity ' + str(sev))
                    res.append(x)
                else:
                    self.logger.critical('didn\'t find any match in out for severity ' + sev )
        except Exception as e:
            self.logger.error('Exception in parsing output ' + str(e))

        return res




    def clone_repository(self,url,project):
        self.logger.debug("reposity is configued for project : " + str(project))
        self.logger.debug("cloning repository in url: " + url)

        path = CONST.BASE_REPO_PATH + project
        cmd = 'git clone ' + url + ' '+ path
        self.logger.debug('cloning ' + project + ' repository into ' + str(path) + ' folder')
        #TODO - need to run clone on SSH host on not on windows.
        try:
            # os.system("ssh -p 3tango root@smg-ib-svr040") #i will run it on the local machine.
            if self.is_directory_exist(path):
                self.logger.debug("Repository was exist on server before the script started. removing it. ")
                self.ssh.run_command('rm -rf '+ path)
            output = self.ssh.run_command(cmd)
        except Exception as e:
            self.logger.error("ERROR: Exception received while trying to clone the repository to : " + CONST.BASE_REPO_PATH + " error message:" + str(e))

        return path

    def is_directory_exist(self,dir):
        self.logger.debug('Checking if directory is exist : ' + str(dir))
        try:
            cmd = '[ -d \"' + dir + '\" ] && echo \"Directory' + dir + 'exists.\"'
            out = self.ssh.run_command(cmd)
            if 'exist' in out[0]:
                self.logger.debug('Dirctory is exist')
                return True
            else:
                self.logger.debug('directory is not exist')
                return False
        except Exception as e:
            self.logger.error('Exception happen during is directory exist function ' + str(e))


class NS():
    def __init__(self,excel):
        self.token = None
        self.folders = None
        self.scans = None
        self.vulnerabilites_by_scan_id = {}
        self.results ={}
        self.my_scans_id = None
        self.aSeasion = requests.Session()
        self.logger = BD.create_logger('nessus.log')
        self.logger.error = CallCounted(self.logger.error)
        self.logger.error = CallCounted(self.logger.error)
        self.authenticate()
        self.list(excel)
        self.logger.info('Done with Nessus')
        print('Done with Nessus. errors: ' + str(self.logger.error.counter))


    def authenticate(self):
        # Username and password will be sent in body of post request
        self.logger.info('authentication for Nessus server has started')
        data = {"username":"admin","password":"3tango"}
        try:
            response = requests.post('https://10.137.41.14:8834/session', data=data, verify=False)
        except Exception as e:
            self.logger.error('Exception received on authenticated with blackduck')
        # check for Success
        if response.ok:
            self.token = ast.literal_eval(response.content.decode('utf-8'))['token']
            self.logger.debug('token used for nessus is : ' + self.token)
            self.aSeasion.headers.update({'X-Cookie':'token=' + self.token})
            self.logger.info('Authentication for Nessus Server is completed successfully')
            self.logger.debug(' Nessus-token is : ' + self.token)
            return 1
        else:
            self.logger.error('Authentication for Nessus server failed. status code is ' + str(response.status_code))
            return 0

    def list(self,excel):
        try:
            response = self.aSeasion.get(' https://10.137.41.14:8834/scans',verify=False)
        except Exception as e:
            self.logger.error('Exception on sending REST to /scans in Nessus')

        if response.status_code == 200:
            self.logger.debug('requests to /scans finish succussfully')
            data = json.loads(response.content)
            self.folders = data['folders']
            self.scans = data['scans']
            self.set_scans_id_folder()
            self.remove_trash_scans()
            self.find_vulnerabilities()
            self.count(excel)


    def count(self,excel):
        try:
            low, medium, high, critical = 0, 0, 0, 0
            for scan_id, scan_lst in self.vulnerabilites_by_scan_id.items():
                self.logger.debug('Check vulnerabilites for scan id ' +str(scan_id))
                for vuln_dct in scan_lst:
                    self.logger.debug('checking vulnerability with plugin name ' +vuln_dct['plugin_name'])
                    sevirity = vuln_dct['severity']
                    if sevirity == 0:
                        low = low +1
                    elif sevirity == 1:
                        medium == medium +1
                    elif sevirity == 2:
                        high = high +1
                    elif sevirity == 3:
                        critical = critical + 1
                    else:
                        self.logger.error('Couldn\'t determine seveiry for bug. values are not 0/1/2/3')
                    project = 'MLNX_OS'
                    severity_arr = []
                    for i in (low,medium,high,critical):
                        severity_arr.append(i)
                    self.results[project]= severity_arr
            self.print_to_csv( excel, low, medium, high, critical, project)
        except Exception as e:
            self.logger.error('Exeption during count function ' +str(e))

    def print_to_csv(self,excel,low,medium,high,critical,project):
        try:
            family = BD.get_family(self.logger, project)
            today = date.today()
            date_ = d2 = today.strftime("%B %d, %Y")
            self.total, level = BD.calculate_total_score(self.logger, project, critical, high, medium, low, 'Nessus')
            row = excel.add_to_row(project, family, 'Vulnerability Scanners', 'Nessus', date_, critical, high, medium, low,level,self.total, 'https://10.137.41.14:8834/#/scans/folders/my-scans')
            excel.write_row(row)
        except Exception as e:
            self.logger.error('Exception during print to csv' + str(e))




    def find_vulnerabilities(self):
        self.logger.info('find vulnerabilites for each scan id')
        vuln = {}
        for scan in self.scans:
            self.logger.debug('getting information about scan id ' + str(scan['id']))
            id = str(scan['id'])
            url = 'https://10.137.41.14:8834/scans/' +id
            try:
                response = self.aSeasion.get(url, verify=False)
            except Exception as e:
                self.logger.error('Exception on sending REST to /vunerabilities in Nessus')

            if response.status_code == 200:
                data = json.loads(response.content)
                self.vulnerabilites_by_scan_id[id] = data['vulnerabilities']





    def remove_trash_scans(self):
        self.logger.info('removing all scans on trash folder')
        new_lst = list()
        for scan in self.scans:
            if scan['folder_id'] == self.my_scans_id:
                new_lst.append(scan)

        self.scans = new_lst


    def set_scans_id_folder(self):
        self.logger.info('setting the folder ID of my scans ')
        for folder in self.folders:
            if folder['name'] == 'My Scans':
                self.my_scans_id =  folder['id']
                self.logger.debug('folder id found for my Scans : ' + str(self.my_scans_id))
                break
        else:
            self.logger.error('folder ID for my scans was not found')

class SSH():
    def __init__(self,logger,host,username,password):
        self.logger = logger
        self.logger.debug('Creating SSH Object')
        self.client = SSHClient()
        self.intial(host,username,password)

    def intial(self, host,username,password):
        try:
            self.logger.info('Start initial SSH configuration for ' + str(host))
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(host,22, username=username, password=password)
        except Exception as e:
            self.logger.error('Exception during SSH initialization' + str(e))

        self.logger.info('initial SSH object is done')

    def run_command(self,cmd):

        self.logger.info('running command via SSH : ' + str(cmd))
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.client.exec_command(cmd)
        except Exception as e:
            self.logger.error('Exception received when running SSH command :' + str(e))

        if ssh_stdout.channel.recv_exit_status():
            self.logger.error('Error appears on SSH command : ' + str(ssh_stderr))
            return ''
        else:
            self.logger.debug('run command over SSH finished succussfully')
            return ssh_stdout.readlines()


class Coverity():
    def __init__(self,excel):
        self.logger = BD.create_logger('coverity.log')
        self.mapper = {'OpenSM' : 'OPENSM',
                       'Windows': 'Windows',
                       'MOFED':'MLNX_OFED',
                        'MellanoxFW':'ConnectX FW',
                       'MellanoxOS':'MLNX_OS'}
        self.vulnerabilities= {}
        self.logger.error = CallCounted(self.logger.error)
        self.links =[]
        self.checker_dict = {}
        self.checker = {}
        self.summary = {}
        self.total = None
        self.load_checkers()
        self.ssh = SSH(self.logger,CONST.SSH_HOST,CONST.SSH_USER,CONST.SSH_PASS)
        self.projects = []
        self.start(excel)
        self.logger.info('Done with Coverity. ')
        print('Done with Coverity errors: '+ str(self.logger.error.counter))

    def load_checkers(self):
        self.logger.info('building checkers model from 4 files')
        for i in range(1,5):
            filename = CONST.COV_FILE_TEMPLATE.replace('<>',str(i))
            self.logger.debug('Trying to open ' + filename)
            f = open(filename, 'r')
            lst = f.readlines()
            dic = {}
            for line in lst:
                if 'security' in line:
                    name = line.split(' ')[0]
                    details = line.split(' ')[1:]
                    details = ' '.join(details).replace('\n','')
                    dic[name] = details
            self.logger.debug('Adding Checkers with Priority ' + str(i) + 'to model')
            self.checker[i] = dic
        self.logger.info('Finished building checkers model successfully')


    def start(self,excel):
        #load csv with vulnerability list into dict
        try:
            self.checker_dict = BD.create_dict_from_csv(self.logger, 'coverity_security.csv')
        except Exception as e:
            self.logger.error('Execption received during reading csv file ' + str(e))

        # get data from all coverity servers
        self.get_all_projects('coverity.mellanox.com','devopstest_dev','123456')
        #self.get_vulnerabilites_by_project_name('coverity.mellanox.com','Admin','Admin1234','OpenSM')
        #self.get_vulnerabilites_by_project_name('coverity.mellanox.com', 'Admin', 'Admin1234', 'Windows')
        #self.get_vulnerabilites_by_project_name('coverity.mellanox.com', 'Admin', 'Admin1234', 'MOFED')
        self.get_vulnerabilites_by_project_name('coverity.mellanox.com', 'fw_rev', '12345678', 'MellanoxFW')
        #self.get_vulnerabilites_by_project_name('coverity.mellanox.com', 'Admin', 'Admin1234', 'MellanoxOS')


        #Parse data and filter by security issues
        self.set_vulnerabilites_priority()
        self.print_results_to_csv(excel)

    def print_results_to_csv(self,excel):
        for project,items in self.vulnerabilities.items():
            low, medium, high, critical = 0, 0, 0, 0
            for dict in items:
                if dict['seveirity'] == 1:
                    critical = critical + 1
                elif dict['seveirity'] == 2:
                    high = high + 1
                elif dict['seveirity'] == 3:
                    medium = medium + 1
                    #if the bug is not security issue just skip the issue
                elif dict['seveirity'] == -1:
                    continue
                else:
                    low = low +1
            try:
                project = self.coverity_mapper(project)
                family = BD.get_family(self.logger, project)
                today = date.today()
                date_ = d2 = today.strftime("%B %d, %Y")
                self.total,level= BD.calculate_total_score(self.logger, project, critical, high, medium, low, 'Coverity')
                row = excel.add_to_row(project, family, 'Static Code Analysis', 'Coverity', date_, critical, high, medium, low,level,self.total,'https://coverity.mellanox.com/reports.html')
                excel.write_row(row)
            except Exception as e:
                self.logger.error('Exception during print_results_to_csv ' + str(e))


    def coverity_mapper(self,project):
        self.logger.debug('trying to get the common name  for '+ project + ' project')
        for project_name, real in self.mapper.items():
            if project_name == project:
                self.logger.debug('found common name for project : ' + real)
                break
        else:
            self.logger.error('Couldn\'t match project name to real name')
            return None

        return real
    def get_priority_from_csv_dict(self,checker):
        self.logger.info('searching for checker name and get his priority')
        checker_list = self.checker_dict['\ufeffName']
        for counter, checker2 in enumerate(checker_list):
            if checker == checker2:
                self.logger.debug('Checker found!')
                priority = self.checker_dict['Impact'][counter]
                break
        else:
            self.logger.critical('Checker wasn\'t found. setting priority to 4')
            return -1

        if priority =='Critical':
            return 1
        elif priority == 'High':
            return 2
        elif priority == 'Medium':
            return 3
        elif priority =='Low':
            return 4
        else:
            return 4


    def set_vulnerabilites_priority(self):
        self.logger.info('Start Filteriing vulnerabilites')

        for project, vuln_lst in self.vulnerabilities.items():
            self.logger.debug('filtering vulnerabilies for project ' + str(project))
            for dict in vuln_lst:
                checker = dict['checker']
                self.logger.debug('Check in checker Model if current Check is security issue and get his priority')
                #priority = self.get_priority_from_checker(checker)
                #TODO- getting prioritiy from CSV file
                priority = self.get_priority_from_csv_dict(checker)
                dict['seveirity'] = priority
            self.logger.debug('Finish set priorities to vulnerabilities in project ' + project)
        self.logger.debug('Finish set priorities to vulnerabilities in all projects')

    def get_priority_from_checker(self, checker):

        for priority,checker_lst in self.checker.items():
            if checker in checker_lst:
                self.logger.debug('Checker found and priority set to ' + str(priority))
                break
        else:
            self.logger.debug('Checker was not found. priority set to 4')
            return 4

        return priority





    def get_vulnerabilites_by_project_name(self,host,username,password,project):
        self.logger.info('Sending command get all vulnerabilities of project ' + project + '  from cov-manage-im tool')
        cmd = r'''/auto/sw_tools/Commercial/Synopsys/Coverity/Coverity_2019.03/linux_x86_64/bin/cov-manage-im  --ssl --on-new-cert trust --host ''' + host + \
              ' --port 8443 --user ' + username + ' --password ' + password + ' --mode defects --show  --project ' + project
        self.logger.debug('cmd : ' + str(cmd))
        #output = self.ssh.run_command(cmd)
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode('utf-8').splitlines()
        lst = []
        if output:
            self.logger.debug('Run command of get all vulnerabilities ended succussfully')
            for line in output[1:]:
                try:
                    dic = {}
                    arr = line.split(',')
                    dic['cid']= arr[0]
                    dic['checker'] = arr[1]
                    dic['status'] = arr[2]
                    dic['classification']= arr[3]
                    dic['owner']= arr[4]
                    dic['seveirity']=arr[5]
                    dic['action'] = arr[6]
                    dic['fix target'] = arr[7]
                    dic['legacy'] = arr[8]
                    dic['merge_key'] = arr[9]
                    lst.append(dic)
                except Exception as e:
                    self.logger.error('Exception during dictionary creation in get all vulnerabilites ' + str(e))
            self.logger.debug('Add dictionary from project ' + project + ' to main dictionary')
            self.vulnerabilities[project] = lst


    def get_all_projects(self,host,username,password):
        self.logger.info('Sending command to receive all projects from cov-manage-im tool')
        cmd = r'''/auto/sw_tools/Commercial/Synopsys/Coverity/Coverity_2019.03/linux_x86_64/bin/cov-manage-im  --ssl --on-new-cert trust --host '''+ host +  \
              ' --port 8443 --user ' + username  + ' --password '+ password + ' --mode projects --show'''
        self.logger.debug('cmd : ' + str(cmd))
        output = self.ssh.run_command(cmd)
        if output:
            self.logger.debug('spliting output of all projects from output')
            try:
                projects = []
                for p in output:
                    tmp = p.replace('\n','')
                    projects.append(tmp)
            except Exception as e:
                self.logger.error('Exception in spliting output to projects' + str(e))

            self.logger.debug('spliting projects is completed succussfully')
            self.projects = projects

class RM():
    def __init__(self,excel):
        self.logger = BD.create_logger('redmime.log')
        self.logger.error = CallCounted(self.logger.error)
        self.aSession = requests.session()
        self.aSession.headers.update({'X-Redmine-API-Key': 'ef7a18c5efd0e6fbcaf8ebea75d7b77bca05589b'})
        self.mapper = {'ConnectX FW':['ConnectX FW Core - Design','ConnectX FW Core - Verification','ConnectX FW System Mng - Design','FW Eth Core - Design'],
                     'MLNX_OFED':['MLNX OFED'],
                     'MLNX_OS':['mlnxOS-Eth','mlnxOS-General','mlnxOS-Security','mlnxOS-Security-IB'],
                       'NEO':['NEO','NEO Server'],
                       'UFM':['UFM','UFM Appliance'],
                       'Windows':['WinOF'],
                       'OpenSM':['OpenSM']
                       }
        self.results ={}
        self.intial_result_list()
        self.start()
        self.write_result_to_csv(excel)
        self.logger.info('Done with Redmine')
        print('Done with Redmine. errors: ' + str(self.logger.error.counter))

    def write_result_to_csv(self,excel):
        self.logger.info('Writing Redmine results to CSV')
        try:
            for product_name, vuln_lst in self.results.items():
                # ['Product', 'Family','Area','Suite','Data','Critial#','High#','Medium#','Low#','Total Score']
                critical,high,medium,low = vuln_lst[0],vuln_lst[1],vuln_lst[2],vuln_lst[3]
                family = BD.get_family(self.logger, product_name)
                today = date.today()
                date_ = d2 = today.strftime("%B %d, %Y")
                total, level = BD.calculate_total_score(self.logger, product_name, critical, high, medium, low, 'Redmine')
                link = '''https://redmine.lab.mtl.com/issues?c%5B%5D=project&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=category&c%5B%5D=fixed_version&c%5B%5D=due_date&c%5B%5D=done_ratio&c%5B%5D=cf_581&f%5B%5D=cf_580&f%5B%5D=status_type&f%5B%5D=subject&f%5B%5D=&group_by=project&op%5Bcf_580%5D=%3D&op%5Bstatus_type%5D=%3D&op%5Bsubject%5D=%21%7E&set_filter=1&sort=id%3Adesc&utf8=%E2%9C%93&v%5Bcf_580%5D%5B%5D=Yes&v%5Bstatus_type%5D%5B%5D=1&v%5Bsubject%5D%5B%5D=cve'''
                row = excel.add_to_row(product_name, family, 'Redmine', 'Redmine', date_, critical, high, medium,low,level, total,link)
                excel.write_row(row)
        except Exception as e:
            self.logger.error('Exception during write results to csv of BD ' + str(e))
        self.logger.debug('finish writing results from BD to CSV')

    def intial_result_list(self):
        self.logger.debug('Intial Result list with Zeros')
        try:
            dict = {}
            for project, project_lst in self.mapper.items():
                lst = [0,0,0,0]
                dict[project] = lst
        except Exception as e:
            self.logger.error('Exception during intialzation of zero lists ' + str(e))
            return None

        self.results = dict

    def start(self):
        issue_list = self.find_security_bugs()
        self.aggregate_results(issue_list)


    def find_cvss_index(self,custom_field_list):
        for counter, value in enumerate(custom_field_list):
            if value['name'] == 'CVSS score':
                self.logger.debug('cvss attribute was found in index '+ str(counter))
                break
        else:
            self.logger.debug('cvss attribute was\'t found in cutum fields')
            return None

        return counter


    def aggregate_results(self, issue_lists):
        self.logger.info('Start Aggregate results from all issues')
        try:
            for issue_list in issue_lists:
                issues = issue_list['issues']
                for issue in issues:
                    project_name = issue['project']['name']
                    priority = issue['priority']['name']
                    custom_field_list = issue['custom_fields']
                    index = self.find_cvss_index(custom_field_list)
                    cvss = issue['custom_fields'][index]['value']
                    if not cvss:
                        self.logger.debug('cvss wasn\'t define for bug. setting cvss 8.0')
                        cvss = 8.0
                    else:
                        cvss = float(cvss)

                    project = self.is_project_exist(project_name)
                    if project:
                        priority_list = self.results[project]
                        if cvss > 9.0:
                            tmp = priority_list[0]
                            tmp = tmp +1
                            priority_list[0]= tmp
                        elif cvss > 7.0:
                            tmp = priority_list[1]
                            tmp = tmp +1
                            priority_list[1]= tmp
                        elif cvss > 5.0:
                            tmp = priority_list[2]
                            tmp = tmp +1
                            priority_list[2]= tmp
                        elif cvss > 0:
                            tmp = priority_list[3]
                            tmp = tmp +1
                            priority_list[3]= tmp
                        else:
                            self.logger.error('Could\'t not find the right priority for redmine issue')

        except Exception as e:
            self.logger.error('Exception received during aggregating results ' + str(e))

    def is_project_exist(self, project_name):
        self.logger.debug('searching for ' + project_name + ' in mapper')
        for real, project_arr in self.mapper.items():
            if project_name in project_arr:
                self.logger.debug('Project was found! returning real name' )
                break
                #return real
        else:
            self.logger.debug('Project was not found ( it\'s totally find if project is not define in your list ')
            return None

        return  real


    def get_number_of_security_bugs(self):
        self.logger.info('sending request to retrieve number of security bugs')
        try:
            params = {'limit': '100', 'offset': '100'}
            url = '''https://redmine.lab.mtl.com/issues.json?c%5B%5D=project&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=category&c%5B%5D=fixed_version&c%5B%5D=due_date&c%5B%5D=done_ratio&c%5B%5D=cf_581&f%5B%5D=cf_580&f%5B%5D=status_type&f%5B%5D=subject&f%5B%5D=&group_by=&op%5Bcf_580%5D=%3D&op%5Bstatus_type%5D=%3D&op%5Bsubject%5D=%21%7E&set_filter=1&sort=id%3Adesc&utf8=%E2%9C%93&v%5Bcf_580%5D%5B%5D=Yes&v%5Bstatus_type%5D%5B%5D=1&v%5Bsubject%5D%5B%5D=cve'''
            # url = r'''https://redmine.lab.mtl.com/issues?c%5B%5D=project&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=category&c%5B%5D=fixed_version&c%5B%5D=due_date&c%5B%5D=done_ratio&f%5B%5D=status_id&f%5B%5D=cf_580&f%5B%5D=&group_by=&limit=1000&op%5Bcf_580%5D=%3D&op%5Bstatus_id%5D=o&set_filter=1&sort=id%3Adesc&utf8=%E2%9C%93&v%5Bcf_580%5D%5B%5D=Yes'''
            response = self.aSession.get(url, params=params, verify=False)

            if response.ok:
                self.logger.info('response is OK')
                self.logger.debug('changing the response content to json format')
                data = json.loads(response.content.decode('utf-8'))
                return data['total_count']
            else:
                self.logger.error(
                    'request failed. status code is not 200. status code is :' + str(response.status_code))
        except Exception as e:
            self.logger.error('Exception during get number of security bugs in redmine : ' + str(e))

    def find_security_bugs(self):
        self.logger.info('Sending request to fetch all security bugs from redmine')
        num = self.get_number_of_security_bugs()
        issues_list=[]
        try:
            offset = 0
            while offset < num:
                params = {'limit':'100','offset':offset}
                url = '''https://redmine-api.mellanox.com/issues.json?c%5B%5D=project&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=category&c%5B%5D=fixed_version&c%5B%5D=due_date&c%5B%5D=done_ratio&f%5B%5D=status_id&f%5B%5D=cf_580&f%5B%5D=tracker_id&f%5B%5D=&group_by=project&op%5Bcf_580%5D=%3D&op%5Bstatus_id%5D=o&op%5Btracker_id%5D=%3D&set_filter=1&sort=id%3Adesc&utf8=%E2%9C%93&v%5Bcf_580%5D%5B%5D=Yes&v%5Btracker_id%5D%5B%5D=1&v%5Btracker_id%5D%5B%5D=28'''
                url = '''https://redmine.lab.mtl.com/issues.json?c%5B%5D=project&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=category&c%5B%5D=fixed_version&c%5B%5D=due_date&c%5B%5D=done_ratio&c%5B%5D=cf_581&f%5B%5D=cf_580&f%5B%5D=status_type&f%5B%5D=subject&f%5B%5D=&group_by=&op%5Bcf_580%5D=%3D&op%5Bstatus_type%5D=%3D&op%5Bsubject%5D=%21%7E&set_filter=1&sort=id%3Adesc&utf8=%E2%9C%93&v%5Bcf_580%5D%5B%5D=Yes&v%5Bstatus_type%5D%5B%5D=1&v%5Bsubject%5D%5B%5D=cve'''
                response = self.aSession.get(url, params =params,verify=False)

                if response.ok:
                    self.logger.info('response is OK')
                    self.logger.debug('changing the response content to json format')
                    data = json.loads(response.content.decode('utf-8'))
                    issues_list.append(data)
                else:
                    self.logger.error('request failed. status code is not 200. status code is :' + str(response.status_code))
                offset = offset + 100
        except Exception as e:
            self.logger.error('Exception During find secuirty bug in redmine : ' + str(e))

        return issues_list



def start_app():
    try:
        while True:
            print('Program has start, type Ctrl+C to Stop.....')
            excel = Excel()
            bd = BD(excel)
            #cov = Coverity(excel)
            #rm = RM(excel)
            #excel.close()
            #time.sleep(10)
    except KeyboardInterrupt:
        print('interrupted! Closing Program Bye Bye.....')

def main():
    main_logger = create_main_logs()
    excel = Excel()
    bd = BD(excel)
    n = NS(excel)
    cov = Coverity(excel)
    rm = RM(excel)
    b = Bandit(excel)
    excel.close()
    print('Done From Main')

if __name__ == '__main__':
    main()
