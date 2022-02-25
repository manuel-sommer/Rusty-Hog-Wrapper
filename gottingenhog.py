import os
import click
from os import listdir
from os.path import isfile, join

@click.group()
def main():
    pass

@main.command()
@click.option('-p', '--project', required=False, help="project")
@click.option('-s', '--startid', required=False, help="startid")
@click.option('-e', '--endid', required=False, help="endid")
@click.option('-r', '--regex', required=False, help="regex")
@click.option('-sf', '--scanfolder', required=False, help="scanfolder")
@click.option('-rf', '--reportfolder', required=False, help="reportfolder")
def scanjira(project,startid,endid,regex,scanfolder,reportfolder):
    GH=GottingenHog()
    GH.scanjira(project=project,startid=startid,endid=endid,regex=regex,scanfolder=scanfolder,reportfolder=reportfolder)

class GottingenHog(object):
    def __init__(self):
        self.user = 'jira-user'
        self.pw = 'jira-password'
        self.jiraurl='https://jira.com'

    def mergejson(self, scanfolder, reportfolder):
        onlyfiles = [f for f in listdir(scanfolder) if isfile(join(scanfolder, f))]
        vulnerabilities=False
        if len(onlyfiles)>1:
            totaloutput = os.path.join(scanfolder,"totaloutput.json")
            for file in onlyfiles:
                with open(scanfolder+"/"+file, 'r') as fin:
                    content = fin.read().splitlines(True)
                    if content[0] == '[]':
                        os.remove(scanfolder + '/' +file)
                    else:
                        if vulnerabilities==False:
                            with open(totaloutput, 'a') as fout:
                                fout.writelines('[') #add "[" at beginning of merged output file (totaloutput)
                                fout.writelines(content[1:-1])
                                fout.close
                            vulnerabilities = True
                        else:
                            with open(totaloutput, 'a') as fout:
                                fout.writelines(',') #add "[" at beginning of merged output file (totaloutput)
                                fout.writelines(content[1:-1])
                                fout.close
            if vulnerabilities == True:
                with open(totaloutput, 'a') as fin:
                    fin.writelines(']')
                    fin.close
                os.system("mv "+totaloutput+" "+ reportfolder)
                os.system('cd ' + scanfolder + ' && rm -f *.json')
            print("JsonMerger is done")

    def scanjira(self, project, startid, endid, regex, scanfolder, reportfolder):
        startid = int(startid)
        endid = int(endid)
        if regex == "passwords":
            regexfile = "/rustyhog/rusty_hog_regex_passwords.json"
        elif regex == "tokens":
            regexfile = "/rustyhog/rusty_hog_regex_tokens.json"
        if endid == -1:
            from atlassian import Jira
            self.jira = Jira(url=self.jiraurl,username=self.user, password=self.pw)
            endid = int(self.jira.get_project_issuekey_last(project=project).split("-")[1])
        while startid <= endid:
            os.system('docker run -it --rm -v /home/ubuntu/rustyhog:/rustyhog -v $HOME/scan_folder:/scan_folder wetfeet2000/gottingen_hog:1.0.10 --entropy --regex ' + regexfile + ' --prettyprint --username ' + self.user + ' --password "' + self.pw + '" --outputfile '+ scanfolder+project+str(startid)+'_got_output.json --url '+ self.jiraurl + ' ' + project + '-'+str(startid))
            startid+=1
        self.mergejson(scanfolder=scanfolder, reportfolder=reportfolder)

if __name__ == '__main__':
    main()