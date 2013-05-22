import fnmatch
import os
from os.path import expanduser
import pefile
#from lxml import etree as XML
import sqlite3

home =r'/mnt/image'
print home

matches = []
#count  = 0;
def BuildDllDB():
  for root, dirnames, filenames in os.walk(home+'/WINDOWS/system32/'): #basic get all dlls in system32 directory
    for filename in fnmatch.filter(filenames, '*.dll'):
      matches.append(os.path.join(root, filename))
    for filename in fnmatch.filter(filenames, '*.exe'):
      matches.append(os.path.join(root, filename))
    for filename in fnmatch.filter(filenames, '*.sys'):
      matches.append(os.path.join(root, filename))
  conn = sqlite3.connect('Symbols.db')
  cur = conn.cursor()
  cur.execute('CREATE TABLE modules (modulename VARCHAR NOT NULL PRIMARY KEY,modname TEXT, codesize INTEGER, checksum INTEGER, majorimageversion INTEGER, minorimageversion INTEGER)')
  cur.execute('CREATE TABLE symbols (symbolid INTEGER PRIMARY KEY AUTOINCREMENT, funcname TEXT, offset TEXT, mname VARCHAR, FOREIGN KEY(mname) REFERENCES modules(modulename))')
  conn.commit()
  print matches, len(matches)

  for filename in matches:
    try:
      print filename
      pe =  pefile.PE(filename)
      modname = filename[filename.rfind('/WINDOWS') + 1:]
      modshortname = filename[filename.rfind('/') + 1:].lower()
      print modname
      print pe.OPTIONAL_HEADER.MajorLinkerVersion
      print pe.OPTIONAL_HEADER.MinorLinkerVersion
      if(len(pe.DIRECTORY_ENTRY_EXPORT.symbols) != 0):
      	cur.execute('INSERT INTO modules (modulename, modname, codesize, checksum, majorimageversion, minorimageversion) VALUES (?,?,?,?,?,?)',(modname,modshortname,pe.OPTIONAL_HEADER.SizeOfCode,pe.OPTIONAL_HEADER.CheckSum,pe.OPTIONAL_HEADER.MajorImageVersion,pe.OPTIONAL_HEADER.MinorImageVersion))
      	conn.commit()
      	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	  offset = '%08x' %exp.address
	  print offset, exp.name
	  cur.execute('INSERT INTO symbols (funcname, offset, mname) VALUES(?,?,?)',(exp.name, str(offset), modname))
    except:
      pass     
     #except sqlite3.OperationalError, msg:
     # print msg 
  conn.commit()
  conn.close()

if __name__ == "__main__":
  BuildDllDB()

