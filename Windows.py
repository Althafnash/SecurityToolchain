import inquirer
from Windows_Modules import hardware,Tcp,Network_ping,IPV4,Target_Info,HTTP,Website_trace,Network_status,enegry_reports,Firewall,Security
import subprocess as sub 

def Windows():
    questions = [
    inquirer.List
        (    'Main',
                message="What You wanna Scan:",
                choices=['Hardware', 
                        'TCP',
                        'Network Ping',
                        'IPV4 Details',
                        'System Information'
                        'HTTP Details'
                        'Trace a Website',
                        'Network status',
                        'Energy Reports',
                        'Firewall data',
                        'Security Data'
                        ],
                carousel=True,
        ),
    ]
    answers = inquirer.prompt(questions)

    if answers['Main'] == 'Hardware':
        sub.run('cls',shell=True)
        hardware()
    elif answers['Main'] == 'Tcp':
        sub.run('cls',shell=True)
        Tcp()
    elif answers['Main'] == 'Network Ping':
        sub.run('cls',shell=True)
        Network_ping()
    elif answers['Main'] == 'IPV4 Details':
        sub.run('cls',shell=True)
        IPV4()
    elif answers['Main'] == 'System Information':
        sub.run('cls',shell=True)
        Target_Info()
    elif answers['Main'] == 'HTTP Details':
        sub.run('cls',shell=True)
        HTTP()
    elif answers['Main'] == 'Trace a Website':
        sub.run('cls',shell=True)
        Website_trace()
    elif answers['Main'] == 'Network status':
        sub.run('cls',shell=True)
        Network_status()
    elif answers['Main'] == 'Energy Reports':
        sub.run('cls',shell=True)
        enegry_reports()
    elif answers['Main'] == 'Firewall data':
        sub.run('cls',shell=True)
        Firewall()
    elif answers['Main'] == 'Security Data':
        sub.run('cls',shell=True)
        Security()