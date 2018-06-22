import subprocess as sub
import time
import sqlite3
import urllib
import json
class SnifferHttp:
     def __init__(self):
         self.lineNum    = 0
         self.httpPakage = []
         self.conn = sqlite3.connect('test.db')
         self.cursor = self.conn.cursor()
         createTableSql = '''create table if not exists httpinfo 
                             (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             timestamp TIMESTAMP default (datetime('now', 'localtime')), 
                             src_ip TEXT,
                             src_port TEXT, 
                             dst_ip TEXT, 
                             dst_port TEXT,
                             host TEXT,
                             request_method TEXT,
                             request_url TEXT,
                             request_line TEXT,
                             cookie TEXT
                             )'''
         self.cursor.execute(createTableSql)
         self.conn.commit()

     def savePakage(self):
         src_ip  = ''
         src_port  = ''
         dst_ip  = ''
         dst_port = ''
         host = ''
         request_method = ''
         request_url = ''
         request_line = ''
         cookie    = ''
         print('数据清空完毕')
         decodejson = json.loads(self.httpPakage)
         print('json解析开始')
         if decodejson['_source']['layers']:
                  try:
                      src_ip = packet['ip.src']
                  except:
                      src_ip = None

                  try:
                      src_port = packet['tcp.srcport']
                  except:
                      src_port = None

                  try:
                      dst_ip = packet['ip.dst']
                  except:
                      dst_ip = None

                  try:
                      dst_port = packet['tcp.dstport']
                  except:
                      dst_port = None

                  try:
                      host = packet['http.host']
                  except:
                      host = None

                  try:
                      request_method = packet['http.request.method']
                  except:
                      request_method = None

                  try:
                      request_url = packet['http.request.full_uri']
                      request_url = urllib.unquote(request_url)
                  except:
                      request_url = None

                  try:
                      request_line = packet['http.request.line']
                  except:
                      request_line = None
     
                  try:
                      cookie = packet['http.cookie']
                  except:
                      cookie = None
                  
                  print('json解析数据如下:',src_ip, src_port, dst_ip, dst_port, host, request_method, request_url, request_line, cookie)
                  self.cursor.execute('''INSERT INTO httpinfo (src_ip, src_port, dst_ip, dst_port, host, request_method, request_url, request_line, cookie) VALUES(?, ?, ?, ?, ?, ?, ?, ?)''',(src_ip, src_port, dst_ip, dst_port, host, request_method, request_url, request_line, cookie))
                  self.conn.commit()
                  print('存储一条数据')
         print('报文初始化')
         self.httpPakage = []

     def run(self):
         p = sub.Popen(["tshark", "-i", "eth0", "-n", "-f", "tcp port http", "-T", "json", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "http.host", "-e", "http.request.method", "-e", "http.request.full_uri", "-e", "http.cookie", "-e", "http.request.line", "-Y", "http.request.method", "-l"], stdin = sub.PIPE, stdout=sub.PIPE)
         self.savePakage(p)


def main():
     SnifferHttp().run()

if __name__ == '__main__':
     main()
