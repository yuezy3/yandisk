import requests
import json
import urllib.parse
import argparse
import sys

"""AppName: ytest
Scopes:
    Yandex.Disk REST API:
        Writing in any place on Yandex.Disk
        Read all of Yandex.Disk
        Access to information about Yandex.Disk
        Access to app folder in Yandex.Disk

ID: 791e....f63
Password: f84....357
Callback URL:
"""
def processArgs():
    parser = argparse.ArgumentParser(description="Yandex Disk console tool")
    parser.add_argument('-c', '--code', help="Input code here so we do not prompt to ask it")
    parser.add_argument('-f', '--config', help="Using config file that contains appid,appsecret,[code],[access_token]")

    _dummy, subCommandArgs = parser.parse_known_args()

    sub_parsers = parser.add_subparsers(title="Subcommand", description="Adding -h on subcommand to see subcommand help")
    parser_ls = sub_parsers.add_parser('ls',help="List remote dir")
    parser_ls.add_argument('ls_dir',nargs="?", default="/" , help="Dir that you want to list, default is root(/)",metavar="path")
    parser_ls.set_defaults(func=lsCommand)
    parser_upload = sub_parsers.add_parser('upload',help="Upload one file to remote")
    parser_upload.add_argument("-r", help="Is url link?")
    parser_upload.add_argument("upload_src", help="Local file that need to be uploaded",metavar="src")
    parser_upload.add_argument("upload_dest", help="remote file that uploaded file should be. Parent path of remote file should exists",metavar="dest")
    parser_upload.set_defaults(func=uploadFileCommand)
    args = parser.parse_args()
    return args, subCommandArgs

env = {
    "appID":"",
    "appSecret":"",
    "manualUrl":"",
    "code":"",
    "tokenUrl":"""https://oauth.yandex.com/token""",
    "token":{},
    "apiHeaders" : {},
    "apiUrlPerfix":"""https://cloud-api.yandex.net/v1/"""
}

def getToken(env = env):
    """will return json like:
    {"token_type": "bearer", "access_token": "AgAAAA...", "expires_in": 31536000, "refresh_token": "1:mqyQrF6d..."}
    """
    while True: 
        codeStr = env["code"] if env["code"] else \
                  input(f"Go to {env['manualUrl']}, \n when it display code(in url?code=xxxxxxx),input that code number here: \n").strip()
        env["code"] = codeStr
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        data = """grant_type=authorization_code""" + \
            f"""&code={codeStr}"""      + \
            f"""&client_id={env["appID"]}"""   + \
            f"""&client_secret={env["appSecret"]}""" 
        r = requests.post(env["tokenUrl"],data=data,headers=headers)
        if r.status_code != 200 : # requests.codes.ok is 200, but python lint report error, so using 200 here
            print(f"Something is wrong when get token from {env['tokenUrl']}, That what we get:\n", r.text)
            if  input(f"\n\n-----------SO.......\nretry?(yes/no): ").lower().startswith('y'):
                env["code"] = "" #clear env["code"] so you input it manual.
            else:
                break
        else: 
            return r.json()
    print("Can't get token from internet.")
    return {} # empty dict is not successed

def lsCommand(args,env=env):
    limit = 20; offset = 0
    pathInfo = getPathInfo(args.ls_dir, limit, offset, env)
    if not pathInfo or pathInfo["type"] == "file": 
        return pathInfo
    pathInfoCollection = pathInfo.copy() # only shollawcopy needed
    while pathInfo and len(pathInfo["ls"])>=limit: 
        pathInfo = getPathInfo(args.ls_dir, limit, offset, env)
        pathInfoCollection["ls"].extend( pathInfo["ls"] if pathInfo else [] )
        offset = offset + limit
    return pathInfoCollection

def getPathInfo(path, limit=20,offset=False,env=env):
    # Metainformation about a file or folder
    url =  env["apiUrlPerfix"] + 'disk/resources' + '?path={}'.format(urllib.parse.quote(path,safe='')) + \
           f"&limit={limit}" + \
           (f"&offset={offset}" if offset else "" )
    ###### url params that used as pagination 
    #@@@@@@@@@@@limit 
    #The number of resources in the folder that should be described in the response (for example, for paginated output).
    #The default value is 20.
    #@@@@@@@@@@@offset
    #The number of resources in the folder that should be skipped in the response (use for paginated output). The list is sorted according to the sort parameter value.
    #Let's say the /foo folder contains three files. For a folder metainformation request with the offset=1 parameter, the Yandex.Disk API returns only the second and third file descriptions.
    r = requests.get(url,headers=env["apiHeaders"])
    if r.status_code == 200:
        rObj = r.json()
        obj = {'type':rObj['type'], 'name': path} # only two type:file or dir
        if rObj['type'] == 'dir':
             obj['ls'] = [ (i['name'], i['type'], 0 if i['type']=='dir' else i['size']) 
                          for i in rObj['_embedded']['items'] ]
        else :
            obj['size'] = rObj['size']
        return obj
    else:
        print(f"Error When get Info with {url}\n",r.text)
        return {}

def uploadFileCommand(args,env=env):
    if uploadFile(args.upload_src, args.upload_dest, env):
        print("Upload done without error\n")
        return True
    else:
        print("Upload error\n")
        return False
def uploadFile(localPath, remotePath,env=env): #parent dir need to be existed 
    url = env["apiUrlPerfix"] + 'disk/resources/upload?path={}'.format(urllib.parse.quote(remotePath,safe='')) #urlencoding filepath
    r = requests.get(url,headers=env["apiHeaders"])
    if r.status_code == 200:
        op = r.json()
        with open(localPath,'rb') as f:
            s = requests.Session()
            req = requests.Request(op['method'],  op['href'], data=f.read())
            prepped = s.prepare_request(req)
            resp = s.send(prepped)
            if resp.status_code >= 300:
                print(f"error when uploading file: \n{resp.text}")
                return False
    else:
        print(f'error when get upload location in remote: \n{r.text}')
        return False
    return True

def perpareEnv(args, env=env):
    if args.code:
        env["code"] = args.code
    if args.config:
        with open(args.config) as f:
            configJson = json.load(f)
            # configJson has to have appID and appSecret key and  their values can't be empty
            if not ( "appID" in configJson and "appSecret" in configJson and \
                     configJson["appID"]   and configJson["appSecret"]            ): 
                print(f"Need appID and appSecret key value in config file {args.config}\n")
                sys.exit()
            env["appID"] = configJson["appID"]
            env["appSecret"] = configJson["appSecret"]
            if (not args.code) and "code" in configJson and configJson["code"]:
                env["code"] = configJson["code"]
            if "token" in configJson and configJson["token"]:
                env["token"] = configJson["token"]
    env["manualUrl"] = """https://oauth.yandex.com/authorize?""" + \
            """response_type=code""" + \
            f"""&client_id={env['appID']}"""
    env["token"] = env["token"] if env["token"] else getToken(env) 
    if not env["token"]: sys.exit() # Still can't have a token? I just exit!
    # now update config to make config.json right
    if args.config: 
        with open(args.config,'w') as f: 
            configJson["code"] = env["code"]
            configJson["token"] = env["token"]
            json.dump(configJson,f,indent=4) 
    env["apiHeaders"] = {"Content-Type":'application/json',
                        "Authorization":f"OAuth {env['token']['access_token']}"} 

if __name__ == "__main__":
    args, subCommandArgs = processArgs()
    perpareEnv(args,env)
    #print(env)
    print(args)
    if subCommandArgs: # specified subcommand
        result = args.func(args,env)
        print(result)
    else:
        print("Need to specify subcommand. Use -h to see full help.")
