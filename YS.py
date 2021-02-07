from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWebEngineWidgets import QWebEngineView
from threading import Thread
from flask import Flask, render_template, request
from urllib import parse
from flask import Flask, render_template, request
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from config import CONFIG,REFERER
import requests
import json
import sqlite3
import time
import numpy as np
import pandas as pd
import random
import base64
import hashlib
import sys
import ctypes
import inspect
import os
import uuid
import string

characters = range(10000001, 10000070)

gee_result = {}
mmt_key = ''
isreloaded = False 
app = Flask(__name__)
app.config.update(
    DEBUG=False,
)
ERRCODE = {
    'Auccess' : 0,
    'ForbiddenAccount' : 1,
    'GetCharsInfoFailed' : 2,
    'WrongPassword' : 3,
    'MissingData' : 4,
    'Noaccountavailable' : 5,
    'Emptycaptcha' : 6,
    'Unknownretcode' : 7,
}

MESSAGE = {
    'Success' : 0,
    'Run_out_of_times' : 1,
    'Data_not_public' : 2,
    'Not_logged_in' : 3
}
def get_url(name,*args):
    url = CONFIG.URL[name].format(*args)
    return url

def get_mmt():
    t = time.time()
    t = int(round(t * 1000))
    '''url = 'https://webapi.account.mihoyo.com/Api/create_mmt?scene_type=1&now={}&reason=bbs.mihoyo.com'.format(
        t)'''
    url = get_url('mmt_url', t)
    proxy = getproxy()
    g = requests.get(url, headers='', proxies=proxy, verify=False, timeout=2)
    return g.json()

def hexdigest(text):
    md5 = hashlib.md5()
    md5.update(text.encode())
    return md5.hexdigest()

def get_ds():
    n = 'h8w582wxwgqvahcdkpvdhbh2w9casgfl'
    i = str(int(time.time()))
    r = ''.join(random.sample(string.ascii_lowercase + string.digits, 6))
    c = hexdigest('salt=' + n + '&t=' + i + '&r=' + r)
    return '{},{},{}'.format(i, r, c)

def get_headers(cookie='', referer='', type_=None):
        if type_ is None:
            header = {
                'x-rpc-device_id':str(uuid.uuid3(
                    uuid.NAMESPACE_URL, cookie)).replace('-', '').upper(),
                # 1:  ios 2:  android 4:  pc web 5:  mobile web
                'x-rpc-client_type': '5',
                'x-rpc-app_version': CONFIG.APP_VERSION,
                'DS': get_ds(),
                'YS-Agent': CONFIG.USER_AGENT,
                'Referer': referer, 
                'Accept-Encoding': 'gzip, deflate, br',
                'Cookie': cookie
                }
        elif type_ == 'login':
            header = {
            'Host': 'webapi.account.mihoyo.com',
            'Connection': 'keep-alive',
            'Content-Length': '460',
            'Accept': 'application/json, text/plain, */*',
            'YS-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://bbs.mihoyo.com',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://bbs.mihoyo.com/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Cookie': '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c; mi18nLang=zh-cn; _gid=GA1.2.153888793.1610692678',
            }
        return header

def getproxy():
    proxy = {'http': '', 'https': ''}
    with open('./data/proxy.txt') as f:
        lines = f.readlines()
        if len(lines) == 0:
            return
        p = random.choice(lines).strip()
        proxy['http'] = p
        proxy['https'] = p
    return proxy

class MyError(Exception):
    '''errcode:
    0: Success.
    1: Account has been forbidden.
    2: Get characters info failed
    3: Wrong password or account.
    4: Missing data
    5: No account available.
    '''
    def __init__(self, errinfo,errcode):
        self.errinfo = errinfo
        self.errcode = errcode
    def __str__(self):
        return repr(self.errinfo)

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.VIEW = {'initview' : 1, 'webview' : 2, 'getting' : 3}
        self.view = 0
        self.accessor = Accessor()
        self.getter = Getter(self.accessor.read('role_id'))
        self.launcher = Launcher(CONFIG.ACCOUNT_PATH + '.' + str(time.strftime("%Y%m%d", time.localtime())))
        self.setWindowTitle('原神')
        self.setGeometry(300, 300, 640, 400)
        self.widget = QWidget()
        self.layout = QHBoxLayout(self)
        self.initview()
        self.widget.setLayout(self.layout)
        self.setCentralWidget(self.widget)
        self.show()

    def setwebview(self):
        if self.view == self.VIEW['webview']:
            return
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        self.webview = QWebEngineView()
        self.webview.load(QUrl("httP://127.0.0.1:5000"))
        self.layout.addWidget(self.webview)
        self.view = self.VIEW['webview']

    def setgetting(self):
        if self.view == self.VIEW['getting']:
            return
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        label_getting=QLabel(self)
        label_getting.setText('正在获取数据...')
        label_getting.setAlignment(Qt.AlignCenter)
        button_stop = QPushButton(self)
        button_stop.setText('停止')
        button_stop.clicked.connect(self.stop_button_clicked)
        self.layout.addWidget(label_getting)
        self.layout.addWidget(button_stop)
        self.view = self.VIEW['getting']

    def initview(self):
        if self.view == self.VIEW['initview']:
            return
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        self.getter.clear_info()
        self.start_button = QPushButton("开始获取")
        self.start_button.clicked.connect(self.start_button_clicked)
        self.dl_button = QPushButton("导出角色数据")
        self.dl_button.clicked.connect(self.dl_button_clicked)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.dl_button)
        self.view = self.VIEW['initview']

    def start_button_clicked(self):
        self.start_timer()
        self.setgetting()

    def dl_button_clicked(self):
        ch = {}
        with open('./data/ch_id.txt', encoding='UTF-8') as f:
            ch_id = f.readlines()
        for c in ch_id:
            name = c[17:].strip()
            ch[name] = self.accessor.read('character','ID' + c[3:11])
        date = time.strftime("%Y%m%d", time.localtime())
        pd.DataFrame(ch).to_csv('./data/result_{}.csv'.format(date), encoding='utf_8_sig')
        reply = QMessageBox.information(
                            self, "成功",  "导出成功！",  QMessageBox.Yes)
        
    def stop_button_clicked(self):
        self.timer.stop()
        self.initview()
        self.accessor.save()

    def start_timer(self):
        global gee_result
        gee_result = {}
        self.timer = QTimer(self)  
        self.timer.timeout.connect(self.operate)  
        self.timer.start(1000)  

    def operate(self):
        global gee_result
        if self.getter.isempty:
            try:
                account_info = self.launcher.login()
            except MyError as e:
                if e.errcode == ERRCODE['Emptycaptcha']:
                    self.setwebview()
                elif e.errcode == ERRCODE['Noaccountavailable']:
                    reply = QMessageBox.information(self, "警告",  e.errinfo,  QMessageBox.Yes)
                    self.timer.stop()
                    self.initview()
                else:
                    reply = QMessageBox.information(self, "警告",  e.errinfo,  QMessageBox.Yes)
                    self.launcher.remove_account()
                return
            login_ticket = account_info['weblogin_token']
            account_id = account_info['account_id']
            cookie_token = account_info['cookie_token']
            self.getter.set_info(cookie_token,login_ticket, account_id)
        self.setgetting()
        try:
            player = self.getter.get_player()
        except MyError as e:
            if e.errinfo == MESSAGE['Run_out_of_times']:
                self.getter.clear_info()
                try:
                    accounts_list = self.launcher.remove_account()
                except MyError as e:
                     reply = QMessageBox.information(
                self, "警告", e.errinfo, QMessageBox.Yes)
            elif e.errinfo == MESSAGE['Not_logged_in']:
                with open('./data/account.txt', 'r+') as f:
                    accounts = f.readlines()
                    line = ''
                    for a in enumerate(accounts):
                        acc = a[1].split(' ')
                        if len(acc) <= 2:
                            continue
                        if self.getter.account_id == acc[2]:
                            line = "{} {}\n".format(acc[0],acc[1])
                            accounts[a[0]] = line
                    f.seek(0)
                    f.truncate()
                    f.writelines(accounts)
                path = './data/account.{}'.format(time.strftime("%Y%m%d", time.localtime()))
                with open(path, 'a+') as f:
                    f.writelines(line)
                self.getter.clear_info()
            elif e.errinfo == MESSAGE['Data_not_public']:
                pass
            else:
                print(str(e.errcode)+ ': ' + str(e.errinfo))
            return
        self.accessor.add(player)

    def closeEvent(self, e):
        self.accessor.save()
        
class Dialog(QMainWindow):
    def __init__(self, parent=None):
        super(Dialog, self).__init__(parent)
        self.setGeometry(300, 300, 640, 400)
        self.widget = QWidget()
        self.layout = QHBoxLayout(self)
        label_getting=QLabel(self)
        label_getting.setText('程序出错啦！')
        label_getting.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(label_getting)
        self.setWindowTitle("error")
        self.setWindowModality(Qt.ApplicationModal)
#登录器
class Launcher(object):
    def __init__(self,account_path):
        self.account = ''
        self.password = ''
        self.account_path = account_path
        self.accounts_list = self.__get_accounts__()
        self.isempty = True

    def __get_accounts__(self):
        account_path = self.account_path
        if not os.path.exists(account_path):
            with open(account_path, 'w+') as f:
                with open('./data/account.txt') as f2:
                    accounts = f2.readlines()
                    while '' in accounts:
                        accounts.remove('')
                    if len(accounts) == 0:
                        raise MyError('无可用账户', ERRCODE['Noaccountavailable'])
                    f.writelines(accounts)
        else:
            with open(account_path) as f:
                accounts = f.readlines()   
            if len(accounts) == 0:
                os.remove(account_path)
                accounts = self.__get_accounts__()
        return accounts
    
    def rsa_encrypt(self, message):
        publickey = '''-----BEGIN PUBLIC KEY-----
                    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7
                    cI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs
                    9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q
                    CgGs52bFoYMtyi+xEQIDAQAB
                    -----END PUBLIC KEY-----'''
        cipher = Cipher_pkcs1_v1_5.new(RSA.importKey(publickey))
        cipher_text = base64.b64encode(cipher.encrypt(message.encode())).decode()
        return cipher_text

    def remove_account(self):
        self.accounts_list.pop(0)
        with open(self.account_path,'w+') as f:
            f.writelines(self.accounts_list)

            
        return self.accounts_list

    def get_account(self):
        try:
            acc_pass = self.accounts_list[0].strip().split(' ')
        except IndexError:
            os.remove(self.account_path)
            self.accounts_list = self.__get_accounts__()
            raise MyError('今日账户查看次数已全部用完,重新读取account！', ERRCODE['Noaccountavailable'])
        return acc_pass

    def get_cookie(self, ticket, account_id):
        t = time.time()
        t = int(round(t * 1000))
        url = get_url('cookie_url', ticket, t)
        cookie = '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c;\
            mi18nLang=zh-cn;_gid=GA1.2.153888793.1610692678; login_uid={}; login_ticket={}'.format(account_id, ticket)
        header = get_headers(cookie,REFERER[1])
        g = self.myrequests('get',url,header)
        return g.json()['data']['cookie_info']['cookie_token']

    def myrequests(self, type_, url, headers, data='', proxies=''):
        if proxies == '':
            proxy = getproxy()
        else:
            proxy = proxies
        if type_ == 'get':
            try:
                r = requests.get(url, headers=headers, proxies=proxy,
                        verify=False, timeout=2)
            except requests.exceptions.ProxyError:
                r = requests.get(url, headers=headers,
                        verify=False, timeout=2)
        if type_ == 'post':
            try:
                r = requests.post(url, data=data, headers=headers,
                        proxies=proxy, verify=False, timeout=2)
            except requests.exceptions.ProxyError:
                r = requests.post(url, data=data, headers=headers,
                        verify=False, timeout=2)
        return r
    
    def set_info(self,account,password):
        self.account = account
        self.password = password
        self.isempty = False
        
    def set_info(self,acc_pass):
        self.account = acc_pass[0]
        self.password = acc_pass[1]
        self.isempty = False
    
    def get_info(self,acc_pass):
        self.account = acc_pass[0]
        self.password = acc_pass[1]
        self.isempty = False
    
    def clear_info(self):
        self.account = ''
        self.password = ''
        self.isempty = True
    
    def login(self):
        acc_pass =self.get_account()
        if len(acc_pass) >= 4:
            account_id = acc_pass[2].strip()
            weblogin_token = acc_pass[3].strip()
            cookie_token = acc_pass[4].strip()
            return {
                'account_id' : account_id,
                'weblogin_token' : weblogin_token,
                'cookie_token' : cookie_token
            }
        global gee_result
        if {} == gee_result:
            raise MyError('',ERRCODE['Emptycaptcha'])
        self.set_info(acc_pass)
        header = get_headers(type_='login')
        url = get_url('login_url')
        data = 'is_bh2=false&account={}&password={}&mmt_key={}&is_crypto=true&geetest_challenge={}&geetest_validate={}&geetest_seccode={}'
        password_rsa = self.rsa_encrypt(self.password)
        password_rsa = parse.quote(password_rsa)
        data = data.format(self.account, password_rsa, mmt_key, gee_result['geetest_challenge'],
                        gee_result['geetest_validate'], gee_result['geetest_seccode'])
        t = self.myrequests('post',url,header,data=data).json()
        gee_result = {}
        p = t['data']['account_info']
        status = t['data']['status']
        if status == -421:
            raise MyError('账号{}已被封禁，请打开account.txt删除'.format(self.account),ERRCODE['ForbiddenAccount'])
        if status == -102:
            raise MyError('账号{}密码格式不正确'.format(self.account),ERRCODE['WrongPassword'])
        if status == -202:
            raise MyError('账号{}密码不正确'.format(self.account),ERRCODE['WrongPassword'])
        cookie_token = self.get_cookie(p['weblogin_token'], self.account)
        p['cookie_token'] = cookie_token
        with open('./data/account.txt', 'r+') as f:
            accounts = f.readlines()
            for a in enumerate(accounts):
                acc = a[1].split(' ')
                acc[-1] = acc[-1].strip()
                if acc[0] == self.account:
                    line = "{} {} {} {} {}\n".format(acc[0],acc[1],p['account_id'],p['weblogin_token'],cookie_token)
                    accounts[a[0]] = line
            f.seek(0)
            f.truncate()
            f.writelines(accounts)
        self.clear_info()
        return p
#获取数据
class Getter(object):
    def __init__(self, bottom_id):
        self.isempty = True
        self.cookie_token = ''
        self.login_ticket = ''
        self.account_id = ''
        self.cookie = ''
        self.bottom_id = bottom_id
        
    def set_info(self, cookie_token, login_ticket, account_id):
        self.cookie_token = cookie_token
        self.login_ticket = login_ticket
        self.account_id = account_id
        self.cookie = '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c; mi18nLang=zh-cn;\
            _gid=GA1.2.153888793.1610692678; login_uid={}; login_ticket={}; account_id={}; cookie_token={}; \
                ltoken=2vhVuLT1aElUzxcT9UYsvuDBLRA0IorNZG6vRvVf; ltuid={}; _gat=1'.format(self.account_id, self.login_ticket, self.account_id, self.cookie_token, self.account_id)
        self.isempty = False
    
    def get_role_id(self):
        self.bottom_id +=  random.randint(1, 100)
        return self.bottom_id
    
    def clear_info(self):
        self.cookie_token = ''
        self.login_ticket = ''
        self.account_id = ''
        self.cookie = ''
        self.isempty = True
    
    def get_chars(self, role_id):
        header = get_headers(self.cookie, REFERER[0])
        url = get_url('get_chars_url',role_id)
        g = self.myrequests('get',url,header)
        return g.json()
    
    def get_abyss(self,role_id,type_):
        header = get_headers(self.cookie,REFERER[0])
        url = get_url('get_abyss_url',type_, role_id)
        g = self.myrequests('get',url,header)
        return g.json()['data']

    def post_chars(self, data):
        header = get_headers(self.cookie, REFERER[0])
        url = get_url('post_chars_url')
        p = self.myrequests('post',url,header,data=data)
        return p.json()

    def get_player_info(self,role_id):
        if self.isempty:
            raise MyError('Getter data is empty', ERRCODE['MissingData'])
        g = self.get_chars(role_id)
        if g['retcode'] == 10101:
            raise MyError(MESSAGE['Run_out_of_times'],ERRCODE['GetCharsInfoFailed'])
        if g['retcode'] == 10102:
            raise MyError(MESSAGE['Data_not_public'],ERRCODE['GetCharsInfoFailed'])
        if g['retcode'] == 10001:
            raise MyError(MESSAGE['Not_logged_in'],ERRCODE['GetCharsInfoFailed'])
        if g['retcode'] != 0:
            raise MyError(g['retcode'],ERRCODE['Unknownretcode'])
        chars = []
        character_ids = ''
        for x in g['data']['avatars']:
            chars.append(x['id'])
            character_ids += str(x['id']) + ','
        character_ids = character_ids.strip(',')
        data = '{{"character_ids":[{0}],"role_id":"{1}","server":"cn_gf01"}}'.format(
            character_ids, role_id)
        p = self.post_chars(data)
        info_all = {}
        for x in p['data']['avatars']:
            char_info = self.get_char_info(x)
            info_all[x['id']] = char_info
        return info_all

    def get_player(self):
        role_id = self.get_role_id()
        player = Player(role_id)
        player.set_characters = self.get_player_info(role_id)
        player.set_abyss(self.get_abyss(role_id, 1))
        player.set_abyss(self.get_abyss(role_id, 2))
        return player
        
    def myrequests(self, type, url, headers, data='', proxies=''):
            if proxies == '':
                proxy = getproxy()
            else:
                proxy = proxies
            if type == 'get':
                try:
                    r = requests.get(url, headers=headers, proxies=proxy,
                            verify=False, timeout=2)
                except requests.exceptions.ProxyError:
                    r = requests.get(url, headers=headers,
                            verify=False, timeout=2)
            if type == 'post':
                try:
                    r = requests.post(url, data=data, headers=headers,
                            proxies=proxy, verify=False, timeout=2)
                except requests.exceptions.ProxyError:
                    r = requests.post(url, data=data, headers=headers,
                            verify=False, timeout=2)
            return r

    def get_char_info(self, charlist):
        char_info = {}
        fate = 0
        for f in charlist['constellations']:
            if f['is_actived']:
                fate += 1
        char_info['fate'] = fate
        char_info['fetter'] = charlist['fetter']
        char_info['level'] = charlist['level']
        char_info['id'] = charlist['id']
        reliquaries = []
        for r in charlist['reliquaries']:
            reliquary = {'id': r['id'], 'level': r['level'],
                        'pos': r['pos'], 'name': r['name']}
            reliquaries.append(reliquary)
        char_info['reliquaries'] = reliquaries
        weapon = charlist['weapon']
        char_info['weapon'] = {'affix_level': weapon['affix_level'],
                            'id': weapon['id'], 'level': weapon['level']}
        return char_info
#保存/读取数据
class Accessor(object):
    def __init__(self):
        if not os.path.exists('./data/ys.db'):
            conn = sqlite3.connect('./data/ys.db')
            cursor = conn.cursor()
            sql = 'CREATE TABLE YS(role_id)'
            cursor.execute(sql)
            sql = 'CREATE UNIQUE INDEX id_index on YS (role_id)'
            cursor.execute(sql)
            for x in characters:
                sql = 'ALTER TABLE YS ADD COLUMN ID{0} TEXT'.format(x)
                cursor.execute(sql)
            sql = 'ALTER TABLE YS ADD COLUMN Abyss1 TEXT'
            cursor.execute(sql)
            sql = 'ALTER TABLE YS ADD COLUMN Abyss2 TEXT'
            cursor.execute(sql)
            conn.commit()
            conn.close()
        self.conn = sqlite3.connect('./data/ys.db')
        self.cursor = self.conn.cursor()
        
    def __del__(self):
        self.conn.commit()
        self.conn.close()
        
    def save(self):
        self.conn.commit()
        
    def add(self,player):
        if isinstance(player, Player):
            cl = 'role_id'
            values = str(player.role_id)
            sql = 'INSERT INTO YS ({0}) VALUES ({1})'.format(cl, values)
            chars = player.characters
            for x in chars.keys():
                cl += ', ID{0}' .format(str(x))
                values += ',' + '"' + str(chars[x]) + '"'
            sql = 'INSERT INTO YS ({0}) VALUES ({1})'.format(cl, values)
            self.cursor.execute(sql)
            end_time = ''
            for x in enumerate(player.abyss.values()):
                values = json.dumps(x[1])
                sql = '''INSERT INTO YS ({0}) VALUES ('{1}')'''.format('Abyss' + str(x[0]+1), values)
                self.cursor.execute(sql)
            self.save()
        
    def read(self, type_, parameter = None):
        if type_ == 'character':
            sql = 'SELECT "{0}" from YS'.format(parameter)
            cursor = self.conn.execute(sql)
            fates = [0, 0, 0, 0, 0, 0, 0]
            for row in cursor:
                if row[0] == None:
                    continue
                i = eval(row[0])['fate']
                fates[i] += 1
            return fates
        if type_ == 'abyss':
            pass
        if type_ == 'role_id':
            sql = 'select * from YS order by role_id desc limit 0,1'
            cursor = self.conn.execute(sql)
            for row in cursor:
                return row[0]
            return 101125314

class Player(object):
    def __init__(self, role_id):
        self._role_id = role_id
        self._characters = {}
        self._abyss = {}
    @property
    def role_id(self):
        return self._role_id
    @property
    def characters(self):
        return self._characters
    @property
    def abyss(self):
        return self._abyss
    def set_abyss(self,data):
        if data['damage_rank'] == []:
            return
        defeat_rank = {}
        for item in data['defeat_rank']:
            defeat_rank[item['avatar_id']] = item['value']
        floors = {}
        for item in data['floors']:
            levels = {}
            battles = {}
            avatars = {}
            for item_l in item['levels']:
                for item_b in item_l['battles']:
                    for item_a in item_b['avatars']:
                        avatars[item_a['id']] = item_a['level']
                    battles[item_b['index']] = avatars
                    battles['star'] = item_l['star']
                levels[item_l['index']] = battles
            floors[item['index']] = levels
        reveal_rank = {}
        for item in data['reveal_rank']:            
            reveal_rank[item['avatar_id']] = item['value']
        take_damage_rank = {}
        for item in data['take_damage_rank']:
            take_damage_rank[item['avatar_id']] = item['value']
        self._abyss[data['end_time']] = {
            'end_time': data['end_time'],
            'damage_rank' : {data['damage_rank'][0]['avatar_id'] : data['damage_rank'][0]['value']},
            'defeat_rank' : defeat_rank,
            'floors' : floors,
            'reveal_rank' : reveal_rank,
            'take_damage_rank' : take_damage_rank
        }
    @characters.setter
    def set_characters(self, characters):
        self._characters = characters

@app.route("/mihoyo", methods=["GET"])
def get_pc_captcha():
    r = get_mmt()
    result = r.get("data", "").get("mmt_data", "")
    global mmt_key
    mmt_key = result.get("mmt_key", "")
    response = {
        "success": 1 if result else 0,
        "gt": result.get("gt", ""),
        "challenge": result.get("challenge", ""),
        "new_captcha": True
    }
    return json.dumps(response)

@app.route("/")
def start():
    return render_template("index.html")

@app.route("/success", methods=['POST'])
def success():
    global gee_result
    gee_result = request.get_json()
    return "success"

if __name__ == "__main__":
    try: 
        app.secret_key = "www"
        t = Thread(target=app.run)
        t.start()
        qapp = QApplication(sys.argv)
        browser = MainWindow()
        sys.exit(qapp.exec_())
    except:
        qapp = QApplication(sys.argv)
        dialog = Dialog()
        dialog.show()
        sys.exit(qapp.exec_())
