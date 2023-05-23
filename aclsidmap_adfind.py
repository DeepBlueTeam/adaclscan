#encoding:gbk
import sys

fout = open('newaclresult.txt', 'ab+')

def is_white_list(tempdn):
    all_white =[
        "CN=Domain Admins,",
        "CN=Account Operators,",
        "CN=Administrators,CN=Builtin,",
        "CN=Cert Publishers,",
        "CN=Enterprise Admins,",
        "CN=Enterprise Key Admins,",
        "CN=Exchange Enterprise Servers,",
        "CN=Exchange Recipient Administrators,",
        "CN=Exchange Servers,",
        "CN=Exchange Trusted Subsystem,",
        "CN=Exchange Windows Permissions,",
        "CN=Key Admins,CN=Users,",
        "CN=Organization Management,",
        "CN=Terminal Server License Servers,",
        "CN=Exchange Organization Administrators,",
    ]
    for item in all_white:
        if tempdn.startswith(item):
            return True
    return False

if len(sys.argv) != 3:
    print('aclsidmap.py sid.txt aclresult.txt')
    sys.exit(0)

mapsid = {}
tmp_sid, tmp_user = '', ''
for line in open(sys.argv[1], 'rb').readlines():
    line = line.decode('gbk').strip('\r\n').strip()
    if line.startswith('dn:'):
        tmp_sid, tmp_user = '', ''
        tmp_user = line.replace('dn:', '')
    if line.startswith('>objectSid: '):
        tmp_sid = line.replace('>objectSid: ', '')
    #if line.startswith('>sAMAccountName: '):
    #    tmp_user = line.replace('>sAMAccountName: ', '')
    if line == '' and tmp_sid != '' and tmp_user != '':
        mapsid[tmp_sid] = tmp_user
        #print(tmp_sid, tmp_user)
    
for line in open(sys.argv[2], 'rb').readlines():
    line = line.decode('utf8').strip('\r\n')
    if line.startswith('    S-'):
        tmp = line.strip(' ')
        if tmp in mapsid.keys():
            tempdn = mapsid[tmp]
            if is_white_list(tempdn):
                continue
            else:
                fout.write(("    "+mapsid[tmp]+"\r\n").encode('utf8'))
        else:
            fout.write(("    "+tmp+"\r\n").encode('utf8'))
    else:
        if is_white_list(line.strip(' ')):
            continue
        else:
            fout.write((line+"\r\n").encode('utf8'))
        