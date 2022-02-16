import os
import click
from os import listdir
from os.path import isfile, join
from atlassian import Confluence

@click.group()
def main():
    pass

@main.command()
@click.option('-sp', '--confluencespace', required=False, help="space")
@click.option('-s', '--startpage', required=False, help="startpage")
@click.option('-l', '--pagelimit', required=False, help="pagelimit")
@click.option('-r', '--regex', required=False, help="regex")
@click.option('-sf', '--scanfolder', required=False, help="scanfolder")
@click.option('-rf', '--reportfolder', required=False, help="reportfolder")
def scanconfluence(confluencespace,startpage,pagelimit,regex,scanfolder,reportfolder):
    EH=EssexHog()
    EH.scanconfluence(space=confluencespace,startpage=startpage,pagelimit=pagelimit,regex=regex,scanfolder=scanfolder,reportfolder=reportfolder)

class EssexHog(object):
    def __init__(self):
        self.user = "jira-user"
        self.pw = "jira-pw"
        self.confluenceurl = "confluence.de"

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

    def scanconfluence(self, space, startpage, pagelimit, regex, scanfolder, reportfolder):
        if regex == "passwords":
            regexfile = "/rustyhog/rusty_hog_regex_passwords.json"
        elif regex == "tokens":
            regexfile = "/rustyhog/rusty_hog_regex_tokens.json"
        confluence = Confluence(url=self.confluenceurl, username=self.user, password=self.pw)
        all_page_info=confluence.get_all_pages_from_space(space, start=startpage, limit=pagelimit, status=None, expand=None, content_type='page')
        for ids in all_page_info:
            outputfile = scanfolder+ids['id']+'_'+space+'_essex_output.json'
            os.system('docker run --rm -v $HOME/rustyhog:/rustyhog -v $HOME/scan_folder:/scan_folder wetfeet2000/essex_hog:1.0.10 --entropy --prettyprint --regex '+regexfile+' --username '+self.user+' --password "'+self.pw+'" --outputfile '+ outputfile + ' --verbose '+ids['id']+' '+ self.confluenceurl)
        self.mergejson(scanfolder=scanfolder, reportfolder=reportfolder)

if __name__ == '__main__':
    main()