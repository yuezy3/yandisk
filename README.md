# A python script that auto yandex disk operation
This is simple script that can list and upload files to yandex disk.

This script will need an config file to operate properly. Using the `config.json.example` as template.
You can just rename it to `config.json`.


## Install and Prepare
You need account in yandex first.

Then, create and register an app in [Yandex Oauth](https://oauth.yandex.com/client/new). In the `Platforms` section, check `Web services`, and set callback URI to `http://localhost`, In the `permissions` section, select `Yandex.Disk REST API` and give all 4 permissions to this app.

*This is important:* Once your registion done, collect your app's ID and Password, go to `config.json` and fill the values. Without correct value in this field, script will not functional.

## Usage 
Using command below to check help document:

    python yandisk.py -h

First time it will ask you to open browser and input proper code:

    $ python yandisk.py -f config.json
    Go to https://oauth.yandex.com/authorize?response_type=code&client_id=xxxxxxx,
    when it display code(in url?code=xxxxxxx),input that code number here:

After open the browser and get the code, input here, script will go on and update `config.json`, next time it will not 
ask you to input code or something manually.

 