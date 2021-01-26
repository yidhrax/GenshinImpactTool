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

characters = range(10000001, 10000070)
idlistpath = './data/idlist.txt'
gee_result = {}
mmt_key = ''
conn = None
reloaded = False 
app = Flask(__name__)
app.config.update(
    DEBUG=False,
)

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.t = Thread(target=runapp)
        self.t.start()
        self.setWindowTitle('原神')
        self.setGeometry(300, 300, 640, 400)
        self.widget = QWidget()
        self.layout = QHBoxLayout(self)
        self.initview()
        self.show()

    def setwebview(self):
        if self.iswebwiew:
            return
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        self.webview = QWebEngineView()
        self.webview.load(QUrl("httP://127.0.0.1:5000"))
        self.layout.addWidget(self.webview)
        self.iswebwiew = True

    def setgetting(self):
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        self.iswebwiew = False
        label_getting=QLabel(self)
        label_getting.setText('正在获取数据...')
        label_getting.setAlignment(Qt.AlignCenter)
        button_stop = QPushButton(self)
        button_stop.setText('停止')
        button_stop.clicked.connect(self.stop_button_clicked)
        self.layout.addWidget(label_getting)
        self.layout.addWidget(button_stop)

    def initview(self):
        for i in range(self.layout.count()):
            self.layout.itemAt(i).widget().deleteLater()
        self.iswebwiew = False
        self.acc_pass = ''
        self.start_button = QPushButton("开始获取数据")
        self.start_button.clicked.connect(self.start_button_clicked)
        self.dl_button = QPushButton("下载角色数据")
        self.dl_button.clicked.connect(self.dl_button_clicked)
        self.get_button = QPushButton("获取可用id")
        self.get_button.clicked.connect(self.get_button_clicked)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.dl_button)
        self.layout.addWidget(self.get_button)
        self.widget.setLayout(self.layout)
        self.setCentralWidget(self.widget)

    def start_button_clicked(self):
        self.start_timer()
        self.setgetting()

    def dl_button_clicked(self):
        ch = {}
        with open('./data/ch_id.txt', encoding='UTF-8') as f:
            ch_id = f.readlines()
        for c in ch_id:
            name = c[17:].strip('\'').strip()
            ch[name] = query(c[3:11])
        date = time.strftime("%Y%m%d", time.localtime())
        pd.DataFrame(ch).to_csv('./data/result_{}.csv'.format(date), encoding='utf_8_sig')
        reply = QMessageBox.information(
                            self, "完成",  "下载完成！",  QMessageBox.Yes)
                
    def get_button_clicked(self):
        self.start_get_timer()
        self.setgetting()

    def stop_button_clicked(self):
        self.timer.stop()
        self.initview()
        conn.commit()

    def start_timer(self):
        with open(idlistpath) as f:
            self.lines = f.readlines()
        global gee_result, reloaded
        self.ch = '1'
        reloaded = False
        gee_result = {}
        self.cookie_token = ''
        self.account_info = ''
        self.timer = QTimer(self)  # 初始化一个定时器
        self.timer.timeout.connect(self.operate)  # 计时结束调用operate()方法
        self.timer.start(1000)  # 设置计时间隔并启动

    def start_get_timer(self):
        with open(idlistpath) as f:
            line = f.readlines()[-1]
            self.role_id = int(line.strip('\''))
        global gee_result, reloaded
        gee_result = {}
        self.cookie_token = ''
        self.account_info = ''
        self.ch = '1'
        reloaded = False
        self.timer = QTimer(self)  
        self.timer.timeout.connect(self.operate_get)  
        self.timer.start(1000) 

    def get_account(self):
        path = './data/account.{}'.format(
            time.strftime("%Y%m%d", time.localtime()))
        if not os.path.exists(path):
            with open(path, 'a+') as f:
                with open('./data/account.txt') as f2:
                    self.accounts = f2.readlines()
                    if len(self.accounts) == 0:
                        reply = QMessageBox.information(
                            self, "警告",  "无可用账户！",  QMessageBox.Yes)
                        os._exit(0)
                    acc = self.accounts[-1]
                    self.accounts.remove(acc)
                    f.writelines(self.accounts)
                    return acc.split(' ')
        else:
            try:
                f = open(path, 'r+')
                self.accounts = f.readlines()
                if len(self.accounts) == 0:
                    reply = QMessageBox.information(
                    self, "警告",  "今日账户查看次数已全部用完,重新读取account",  QMessageBox.Yes)
                    f.close()
                    os.remove(path)
                    acc = self.get_account()
                    return acc
                acc = self.accounts[0]
                self.accounts.remove(acc)
                f.seek(0)
                f.truncate()
                f.writelines(self.accounts)
                f.close()
                acc = acc.split(' ')
                acc[-1] = acc[-1].strip()
                return acc
            except:
                f.close()
                raise Exception

    def operate(self):
        if len(self.lines) <= 10:
            reply = QMessageBox.information(
                self, "警告",  "可用id不足",  QMessageBox.Yes)
            self.initview()
            self.timer.stop()
            return
        if self.ch == '1':
            global reloaded, gee_result
            if gee_result == {}:
                if self.acc_pass == '':
                    self.acc_pass = self.get_account()
                if len(self.acc_pass) >= 4:
                    self.account_info = {
                        'account_id':self.acc_pass[2].strip(),
                        'weblogin_token':self.acc_pass[3].strip(),
                        'cookie_token':self.acc_pass[4].strip()
                    }
                    self.acc_pass = ''
                    gee_result = '1'
                else:   
                    if not reloaded:
                        self.setwebview()
                        reloaded = True
                    return
            else:
                try:
                    self.setwebview()
                    self.account_info = self.login(self.acc_pass[0],self.acc_pass[1])
                except:
                    return
            if self.account_info == None:
                self.acc_pass = ''
                reloaded = False
                gee_result = {}
                return
        
        login_ticket = self.account_info['weblogin_token']
        account_id = self.account_info['account_id']
        cookie_token = self.account_info['cookie_token']
        role_id = self.lines[0].strip('\'').strip()
        self.ch = get_chars_byid(role_id, account_id,login_ticket, cookie_token)
        if self.ch == '1':
            gee_result = {}
            reloaded = False
            self.acc_pass = ''
            return
        if self.ch == '3':
            with open('./data/account.txt', 'r+') as f:
                accounts = f.readlines()
                line = ''
                for a in enumerate(accounts):
                    acc = a[1].split(' ')
                    acc[-1] = acc[-1].strip()
                    if acc[0] ==self.acc_pass_b[0]:
                        line = "{} {}\n".format(acc[0],acc[1])
                        accounts[a[0]] = line
                f.seek(0)
                f.truncate()
                f.writelines(accounts)
            path = './data/account.{}'.format(time.strftime("%Y%m%d", time.localtime()))
            with open(path, 'a+') as f:
                f.writelines(line)
        insert(self.ch, role_id)
        self.lines.remove(self.lines[0])
        with open(idlistpath, 'w+') as f:
            f.writelines(self.lines)

    def operate_get(self):
        global gee_result
        if self.cookie_token == '':
            with open('./data/account.txt') as f:
                    self.accounts = f.readlines()
                    if len(self.accounts) == 0:
                        reply = QMessageBox.information(
                            self, "警告",  "无可用账户！",  QMessageBox.Yes)
                        os._exit(0)
                    self.acc_pass = self.accounts[-1].split(' ')
            if len(self.acc_pass) >= 4:
                    self.account_info = {
                        'account_id':self.acc_pass[2].strip(),
                        'weblogin_token':self.acc_pass[3].strip(),
                        'cookie_token':self.acc_pass[4].strip()
                    }
            else:
                self.setwebview()
                if gee_result == {}:
                    return
                self.account_info = self.login(self.acc_pass[0], self.acc_pass[1])
                self.account_info['cookie_token'] = get_cookie(self.account_info['weblogin_token'],\
                    self.account_info['account_id'])  
        
        login_ticket = self.account_info['weblogin_token']
        account_id = self.account_info['account_id']
        cookie_token = self.account_info['cookie_token']
        self.role_id += random.randint(0, 100)
        self.ch = get_chars_byid(self.role_id,account_id, login_ticket, cookie_token)
        if self.ch == '1':
            with open(idlistpath, 'a') as f:
                f.write(str(self.role_id) + '\n')
        elif self.ch not in ['1','2','3']:
            insert(self.ch, self.role_id)

    def closeEvent(self, e):
        conn.commit()
        conn.close()
        os._exit(0)

    def login(self,account,password):
        header = {
            'Host': 'webapi.account.mihoyo.com',
            'Connection': 'keep-alive',
            'Content-Length': '460',
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75',
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
        url = 'https://webapi.account.mihoyo.com/Api/login_by_password'
        data = 'is_bh2=false&account={}&password={}&mmt_key={}&is_crypto=true&geetest_challenge={}&geetest_validate={}&geetest_seccode={}'
        password_rsa = rsa_encrypt(password)
        password_rsa = parse.quote(password_rsa)
        data = data.format(account, password_rsa, mmt_key, gee_result['geetest_challenge'],
                        gee_result['geetest_validate'], gee_result['geetest_seccode'])
        t = myrequests('post',url,header,data=data).json()
        p = t['data']['account_info']
        self.setgetting()
        if p == None:
            if t['data']['info'] == '您的账号存在安全风险被冻结，请联系account_kf@mihoyo.com处理':
                 reply = QMessageBox.information(
                self, "警告",  "账号{}已被封禁，请打开account.txt删除".format(account),  QMessageBox.Yes)
            return
        cookie_token = get_cookie(p['weblogin_token'], account)
        p['cookie_token'] = cookie_token
        with open('./data/account.txt', 'r+') as f:
            accounts = f.readlines()
            for a in enumerate(accounts):
                acc = a[1].split(' ')
                acc[-1] = acc[-1].strip()
                if acc[0] == account:
                    line = "{} {} {} {} {}\n".format(acc[0],acc[1],p['account_id'],p['weblogin_token'],cookie_token)
                    accounts[a[0]] = line
            f.seek(0)
            f.truncate()
            f.writelines(accounts)
        return p
    
    def get_account(self):
        path = './data/account.{}'.format(
            time.strftime("%Y%m%d", time.localtime()))
        if not os.path.exists(path):
            with open(path, 'a+') as f:
                with open('./data/account.txt') as f2:
                    accounts = f2.readlines()
                    if len(accounts) == 0:
                        reply = QMessageBox.information(
                            self, "警告",  "无可用账户！",  QMessageBox.Yes)
                        os._exit(0)
                    acc = accounts[-1]
                    accounts.remove(acc)
                    f.writelines(accounts)
                    return acc.split(' ')
        else:
            try:
                f = open(path, 'r+')
                accounts = f.readlines()
                if len(accounts) == 0:
                    self.timer.stop()
                    self.initview()
                    reply = QMessageBox.information(
                    self, "警告",  "今日账户查看次数已全部用完,重新读取account",  QMessageBox.Yes)
                    f.close()
                    os.remove(path)
                    acc = self.get_account()
                    return acc
                acc = accounts[0]
                accounts.remove(acc)
                f.seek(0)
                f.truncate()
                f.writelines(accounts)
                f.close()
                acc = acc.split(' ')
                acc[-1] = acc[-1].strip()
                return acc
            except:
                f.close()
                raise Exception

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
    data = request.get_json()
    global gee_result, reloaded
    gee_result = data
    return "success"

def get_mmt():
    t = time.time()
    t = int(round(t * 1000))
    url = 'https://webapi.account.mihoyo.com/Api/create_mmt?scene_type=1&now={}&reason=bbs.mihoyo.com'.format(
        t)
    g = myrequests('get', url, headers='')
    return g.json()

def get_chars(role_id, cookie_token, login_ticket, account_id):
    header = {
        'Host': 'api-takumi.mihoyo.com',
        'Connection': 'keep-alive',
        'Accept': 'application/json, text/plain, */*',
        'x-rpc-app_version': '2.3.0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75',
        'x-rpc-client_type': '888',  # tag
        'Origin': 'https://webstatic.mihoyo.com',
        'Sec-Fetch-Site': 'same-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Ds': '1610783009,wcSJWS,0983f81a85a1770953eddab80db2cfeb',
        'Referer': 'https://webstatic.mihoyo.com/',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    }
    cookie = '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c; mi18nLang=zh-cn;\
        _gid=GA1.2.153888793.1610692678; login_uid={}; login_ticket={}; account_id={}; cookie_token={}; \
            ltoken=2vhVuLT1aElUzxcT9UYsvuDBLRA0IorNZG6vRvVf; ltuid={}; _gat=1'.format(account_id, login_ticket, account_id, cookie_token, account_id)
    header['Cookie'] = cookie
    url = 'https://api-takumi.mihoyo.com/game_record/genshin/api/index?server=cn_gf01&role_id={0}'.format(
        role_id)
    g = myrequests('get',url,header)
    return g.json()

def postchars(data, cookie_token, login_ticket, account_id):
    header = {
        'Host': 'api-takumi.mihoyo.com',
        'Connection': 'keep-alive',
        'Content-Length': '222',
        'Accept': 'application/json, text/plain, */*',
        'Ds': '1610783009,wcSJWS,0983f81a85a1770953eddab80db2cfeb',
        'x-rpc-app_version': '2.2.1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.67 Safari/537.36 Edg/87.0.664.55',
        'x-rpc-client_type': '888',
        'Content-Type': 'application/json;charset=UTF-8',
        'Origin': 'https://webstatic.mihoyo.com',
        'Sec-Fetch-Site': 'same-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://webstatic.mihoyo.com/',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    }
    cookie = '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c; mi18nLang=zh-cn;\
        _gid=GA1.2.153888793.1610692678; login_uid={}; login_ticket={}; account_id={}; cookie_token={}; \
            ltoken=2vhVuLT1aElUzxcT9UYsvuDBLRA0IorNZG6vRvVf; ltuid={}; _gat=1'.format(account_id, login_ticket, account_id, cookie_token, account_id)
    header['Cookie'] = cookie
    url = 'https://api-takumi.mihoyo.com/game_record/genshin/api/character'
    p = myrequests('post',url,header,data=data)
    return p.json()

def rsa_encrypt(message):
    publickey = '''-----BEGIN PUBLIC KEY-----
                MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7
                cI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs
                9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q
                CgGs52bFoYMtyi+xEQIDAQAB
                -----END PUBLIC KEY-----'''
    cipher = Cipher_pkcs1_v1_5.new(RSA.importKey(publickey))
    cipher_text = base64.b64encode(cipher.encrypt(message.encode())).decode()
    return cipher_text

def get_cookie(ticket, account_id):
    t = time.time()
    t = int(round(t * 1000))
    url = 'https://webapi.account.mihoyo.com/Api/cookie_accountinfo_by_loginticket?login_ticket={}&t={}'.format(
        ticket, t)
    header = {
        'Host': 'webapi.account.mihoyo.com',
        'Connection': 'keep-alive',
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75',
        'Origin': 'https://bbs.mihoyo.com',
        'Sec-Fetch-Site': 'same-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://bbs.mihoyo.com/',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    }
    header['Cookie'] = '_ga=GA1.2.315542037.1607442735; UM_distinctid=176430da7561cd-0f9974eb924088-5a301348-144000-176430da75731c;\
        mi18nLang=zh-cn;_gid=GA1.2.153888793.1610692678; login_uid={}; login_ticket={}'.format(account_id, ticket)

    g = myrequests('get',url,header)
    return g.json()['data']['cookie_info']['cookie_token']

def insert(chars, role_id):
    cursor = conn.cursor()
    cl = 'role_id'
    values = str(role_id)
    for x in chars.keys():
        cl += ',"{0}"' .format(str(x))
        values += ',' + '\"' + str(chars[x]) + '\"'

    sql = 'INSERT INTO User ({0}) VALUES ({1})'.format(cl, values)
    cursor.execute(sql)
    cursor.close()
    
def query(char):
    cursor = conn.cursor()
    sql = 'SELECT "{0}" from User'.format(char)
    cursor = conn.execute(sql)
    fates = [0, 0, 0, 0, 0, 0, 0]
    for row in cursor:
        if row[0] == None:
            continue
        i = eval(row[0])['fate']
        fates[i] += 1
    return fates

def runapp():
    app.secret_key = "www"
    app.run()

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

def get_char_info(char):
    char_info = {}
    fate = 0
    for f in char['constellations']:
        if f['is_actived']:
            fate += 1
    char_info['fate'] = fate
    char_info['fetter'] = char['fetter']
    char_info['level'] = char['level']
    char_info['id'] = char['id']
    reliquaries = []
    for r in char['reliquaries']:
        reliquary = {'id': r['id'], 'level': r['level'],
                     'pos': r['pos'], 'name': r['name']}
        reliquaries.append(reliquary)
    char_info['reliquaries'] = reliquaries
    weapon = char['weapon']
    char_info['weapon'] = {'affix_level': weapon['affix_level'],
                           'id': weapon['id'], 'level': weapon['level']}
    return char_info

def get_chars_byid(id, account_id, login_ticket, cookie_token):
    g = get_chars(id, cookie_token, login_ticket, account_id)
    if g['message'] == 'You can access the genshin game records of up to 30 other people':
        return '1'
    if g['message'] == 'Data is not public for the user':
        return '2'
    if g['message'] == 'Please login':
        return '3'
    chars = []
    character_ids = ''
    for x in g['data']['avatars']:
        chars.append(x['id'])
        character_ids += str(x['id']) + ','
    character_ids = character_ids.strip(',')
    data = '{{"character_ids":[{0}],"role_id":"{1}","server":"cn_gf01"}}'.format(
        character_ids, id)
    p = postchars(data, cookie_token, login_ticket, account_id)
    info_all = {}
    for x in p['data']['avatars']:
        char_info = get_char_info(x)
        info_all[x['id']] = char_info
    return info_all

def myrequests(type, url, headers, data='', proxies=''):
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

def init():
    if os.path.exists('./data/ys.db'):
        return
    conn = sqlite3.connect('./data/ys.db')
    cursor = conn.cursor()
    sql = 'CREATE TABLE User(role_id)'
    cursor.execute(sql)
    for x in characters:
        sql = 'ALTER TABLE User ADD COLUMN  "{0}" INTEGER'.format(x)
        cursor.execute(sql)
    cursor.close()
    conn.commit()
    conn.close()


if __name__ == "__main__":
    conn = sqlite3.connect('./data/ys.db')
    try:
        init()
        t = Thread(target=runapp)
        t.start()
        qapp = QApplication(sys.argv)
        browser = MainWindow()
        sys.exit(qapp.exec_())
    except:
        qapp = QApplication(sys.argv)
        dialog = Dialog()
        dialog.show()
        sys.exit(qapp.exec_())
    finally:
        conn.commit()
        conn.close()
