<h1 align="center">📝 SSL HELPER 📝</h1>
<h3 align="center">SSL CONVERTER AND GENERATOR BATCH SCRIPT</h3>
                                               
```bash


___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v1.0



```


# ABOUT

I created this batch script out of the need to automate my team's SSL certificate generation process.
we choose batch because we needed a lightweight solution. 
so no need to remember all the openssl codes anymore.
This project has moved from just a simple Batch Script to a sophisticated SSL Helpmate for all your SSL Needs

## Dependencies

This script leverages on openssl executable 'openssl.exe' and it's included in this package. for any reason the script fails to find openssl.exe in its working directory in your PC, it will fetch it from it's github repo, provided you have an internet connection and you can reach github.com

This script also leverages on openssl.conf file, the file is particularly important if you intent to use the self certification option, the script will as well fetch this config file from its github's repo if it doesnt find it within its working directory.

This script makes use of JAVA Keytool in some modules, It assumes you have Java Keytool installed(comes with JAVA application) and set in your Environment Variable.

NOTE: For now it doesnt matter if you have openssl in your environment variable, if its not in the script's working directory, the script would not run.

```bash
openssl.exe | openssl.conf | keytool.exe
```

## Usage

```python
# copy the files to your computer
git clone https://github.com/Johnng007/SSL-HELPER.git

# run SSLHELPER.bat
sslhelper.bat
```
NOTE: you dont need administrator priviledges to run the batch file, even in a domain joined PC.
      Powershell Plugins has been added to enhance the features, there my be a powershell execution policy in place if you are in a controlled environment.

## Features
```bash

   =================================
     CONVERTING FROM PEM
   =================================
     1. PEM to DER.
     2. PEM to P7B.
     3. PEM(.PEM, .CRT, .CER) TO PFX

   =================================
     CONVERTING FROM DER
   =================================
     4. DER(.CRT .CER .DER) TO PEM.
     5. DER TO CER.

   =================================
     CONVERTING FROM P7B
   =================================
     6. P7B TO PEM.
     7. P7B TO PFX.
     8. P7B TO CER.

   =================================
     CONVERTING FROM PFX
   =================================
     9. PFX TO PEM.
    10. EXTRACT KEY File From PFX
    11. PFX TO CRT

   =================================
     CONVERTING FROM CER
   =================================
    12. CER TO P7B
    13. CER TO PFX
    14. CER TO DER

   =================================
     DECRYPT A KEY File
   =================================
    15. DECRYPT KEY FILE

   =================================
     CERTIFICATE GENERATION
   =================================
    16. GENERATE SELF SIGNED
    17. GENERATE SELF SIGNED AUTO

   ====================================================
      AUDIT
   ====================================================
    18. CHECK SSL DETAILS AND VALIDITY
    19. CHECK SSL DETAILS AND VALIDITY (MULTIPLE URLs)

   =======================================
      ADVANCED (POWERSHELL PLUGINS)
   =======================================
    20. PLUGINS

    21. Close.
    
    [--u]Usage  [--h]Help [--update]Update
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Plugins are welcomed!!! you can enhance the features of sslhelper by adding powershell plugins in the plugin directory, then edit index.bat and point to your plugin.


## License
[MIT](https://mit.com/licenses/mit/)


<h3 align="left">Support:</h3>
<p><a href="https://www.buymeacoffee.com/ebuka"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="ebuka" /></a></p><br><br>

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://linkedin.com/in/ebuka john onyejegbu" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="ebuka john onyejegbu" height="30" width="40" /></a>
</p>

