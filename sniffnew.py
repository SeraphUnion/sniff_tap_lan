import subprocess as sub
import time
import sqlite3
import urllib
class SnifferHttp:
     def __init__(self):
         self.filter = ['.jpg', '.png', '.gif', '.css', '.js', '.swf']
         self.lineNum    = 0
         self.httpPakage = []
         self.conn = sqlite3.connect('httpdata.db')
         self.cursor = self.conn.cursor()
         createTableSql = '''create table if not exists httpinfo 
                             (
                             id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             raw_data TEXT, 
                             host TEXT, 
                             src_ip TEXT, 
                             tar_ip TEXT, 
                             time TEXT, 
                             timestamp TIMESTAMP default (datetime('now', 'localtime'))
                             )'''
         self.cursor.execute(createTableSql)
         self.conn.commit()
     def savePakage(self):
         isFilter = False
         src_ip  = ''
         tar_ip  = ''
         host    = ''
         rawData = ''
         now_time = time.strftime('%Y-%m-%d %H:%I:%S')
         for s in self.httpPakage:
             if s.startswith('T '):
                ips = s.split(' ')
                src_ip = ips[1].split(':')[0].strip('\n')
                tar_ip  = ips[3].split(':')[0].strip('\n')
             if s[0:4].lower() == 'host':
                host = s.split(':')[1].strip('\n')
             if s[0:3].lower() == 'get':
                q = s.split(' ')[1].lower()
                for f in self.filter:
                    if q.find(f) != -1:
                        isFilter = True
         rawData = ''.join(self.httpPakage)
         rawData = urllib.unquote(rawData)
         if not isFilter:
             self.cursor.execute('''INSERT INTO httpinfo (raw_data, host, src_ip, tar_ip, time) VALUES(?, ?, ?, ?, ?)''',(rawData, host, src_ip, tar_ip, now_time))
             self.conn.commit()
         self.httpPakage = []
     def run(self):
         p = sub.Popen(['ngrep', '-q', '-W', 'byline', '^(GET|POST).*'], stdout=sub.PIPE)
         for row in iter(p.stdout.readline, b''):
             if self.lineNum > 2 and row != '\n':
                if row != '.\n':
                    self.httpPakage.append(row)
                else:
                    try:
                        self.savePakage()
                    except Exception as e:
                        pass
             else:
                self.lineNum += 1
def main():
     SnifferHttp().run()

if __name__ == '__main__':
     main()
