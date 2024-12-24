import inquirer
from Windows import Windows
from CyberSceurity import CyberSecurity
import subprocess as sub 

def main():
  questions = [
    inquirer.List
    (    'Main',
          message="Choice a branch",
          choices=['Windows', 
                    'Linux',
                    'CyberSecurity' 
                    ],
          carousel=True,
    ),
  ]
  answers = inquirer.prompt(questions)

  if answers['Main'] == 'Windows':
    sub.run('cls',shell=True)
    Windows()
    
  if answers['Main'] == 'Linux':
    sub.run('cls',shell=True)
    Windows()

  if answers['Main'] == 'CyberSecurity':
    sub.run('cls',shell=True)
    CyberSecurity()

main()