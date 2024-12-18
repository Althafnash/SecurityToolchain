import inquirer
import subprocess as sub 
from Cybersecurity_Modules import IP_Scan,Hostname_scan,Url_Scan,Domain_scan

def CyberSecurity():
    questions = [
    inquirer.List
        (    'Main',
                message="What You wanna Scan:",
                choices=['OTXIP_scan', 
                        'OTXHostname_scan',
                        'OTXUrl_Scan',
                        'OTXDomain_scan',
                        ],
                carousel=True,
        ),
    ]
    answers = inquirer.prompt(questions)

    if answers['Main'] == 'OTXIP_scan':
        sub.run('cls',shell=True)
        IP_Scan()
    elif answers['Main'] == 'OTXHostname_scan':
        sub.run('cls',shell=True)
        Hostname_scan()
    elif answers['Main'] == 'OTXUrl_Scan':
        sub.run('cls',shell=True)
        Url_Scan()
   