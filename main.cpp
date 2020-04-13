#include <iostream>
#include <unistd.h>
#include <climits>
#include <sys/param.h>
#include <vector>
#include <bits/stdc++.h>

using namespace std;
string logdir;
string confdir;

string pkexec = "pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY ";
string sudo = "sudo -S ";
string authorizer = pkexec;

std::string getexedir()
{
    char result[ PATH_MAX ];
    ssize_t count = readlink( "/proc/self/exe", result, PATH_MAX );
    std::string appPath = std::string( result, (count > 0) ? count : 0 );

    std::size_t found = appPath.find_last_of("/\\");
    return appPath.substr(0,found);
}

string getCurrentDateTime( const string& s ){
    time_t now = time(nullptr);
    struct tm  tstruct{};
    char  buf[80];
    tstruct = *localtime(&now);
    if(s=="now")
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    else if(s=="date")
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
    return string(buf);
}

inline void Logger( const string& logMsg ){
    string filePath = logdir+"/log_"+getCurrentDateTime("date")+".log";
    string now = getCurrentDateTime("now");
    ofstream ofs(filePath.c_str(), std::ios_base::out | std::ios_base::app );
    ofs << now << '\t' << logMsg << '\n';
    ofs.close();
}


string executeConnection(const string& path){
    string trustedConfigString = "--trusted-cert ";
    string trustedCert;
    bool hasError= false;
    int trustedConfigStringSize = trustedConfigString.size();
    char line[1000];

    string command = authorizer+"openfortivpn --config "+path;

    FILE * fs = popen(command.data(), "r");

    while(fgets(line, sizeof(line), fs) != nullptr) {
        string decodedLine = line;
        size_t pos = decodedLine.find(trustedConfigString);
        hasError = hasError || ((int) decodedLine.find("ERROR")) != -1;
        Logger(decodedLine);
        if(pos != -1){
            trustedCert = "TRUSTED_CERT|"+decodedLine.substr(pos+trustedConfigStringSize);
        }
    }
    pclose(fs);

    if(!trustedCert.empty()){
        return trustedCert;
    }

    if(hasError){
        return "CONNECTION_ERROR";
    }

    system("notify-send Vpn \"Process ended!\"");

    return "ENDED";

}

void addTrustCert(const string& configName, const string& config){
    std::ofstream outfile;
    outfile.open(confdir+"/"+configName, std::ios_base::app); // append instead of overwrite
    outfile << "trusted-cert="+config+"\n";
    outfile.close();
}

int addConfig(const string& configName){
    string config;
    string configtxt;
    std::ofstream outfile (confdir+"/"+configName);

    cout << "hostname:" << endl;
    cin >> config;
    configtxt += "host="+config+"\n";

    cout << "port:" << endl;
    cin >> config;
    configtxt += "port="+config+"\n";

    cout << "username:" << endl;
    cin >> config;
    configtxt += "username="+config+"\n";

    cout << "password:" << endl;
    cin >> config;
    configtxt += "password="+config;

    cout << "trusted-cert [optional  (type - to skip) ]" << endl;
    cin >> config;
    if(config!="-"){
        configtxt += "\ntrusted-cert="+config;
    }

    outfile << configtxt << std::endl;

    outfile.close();

    cout << "Done!" << endl;
    return 0;
}

void writeToParent(const int* fd, const string& msg){
    close(fd[0]);

    string::size_type size = msg.size();
    write(fd[1], &size, sizeof(size));
    write(fd[1], msg.c_str(), msg.size());
}

string readChild(const int* fd, int timeoutSecs){

    fd_set set;
    int filedesc = fd[0];
    struct timeval timeout{};
    int rv;
    FD_ZERO(&set); /* clear the set */
    FD_SET(filedesc, &set); /* add our file descriptor to the set */

    timeout.tv_sec = timeoutSecs;
    timeout.tv_usec = 0;

    rv = select(filedesc + 1, &set, NULL, NULL, &timeout);
    if(rv == -1) {
        return "error";
    } else if(rv == 0) {
        return "timeout";
    } else {
        close(fd[1]);
        string::size_type size;
        read(filedesc, &size, sizeof(size));
        string str(size, ' ');
        read(filedesc, &str[0], size);
        return str;
    }
}

vector<string> splitKey(string str,string search){
    vector<string> ret;
    int pos = str.find(search);
    if(pos!=-1) {
        ret.push_back(str.substr(0, pos));
        ret.push_back(str.substr(pos+search.size()));
    }else{
        ret.push_back(str);
    }
    return ret;
}
int numTent=0;
int connect(const string& config){

    int fd[2];
    pipe(fd);

    pid_t pid = fork();
    if (pid == 0) {
        string ret = executeConnection(confdir+"/"+config);
        writeToParent(fd,ret);
        return 0;
    } else {
        cout << "Wait Until you can close the terminal (up to 30 sec)" << endl;
        string childStatus = readChild(fd, 30);
        if(childStatus=="timeout"){
            cout << "Process Started" << endl;
            cout << "You can close the terminal now" << endl;
            return 0;
        }else if(childStatus=="error"){
            cout << "A error occurred trying to initiate process;" << endl;
            if(!kill(pid, SIGKILL)){
                cout << "Failed to end child process" << endl;
            }
            return 1;
        } else {

            vector<string> result = splitKey(childStatus, "|");
            if(result.size()>1){
                if(result[0]=="TRUSTED_CERT"&&numTent<=3){
                    cout << "Would you like to add the certificate below and proceed with the connection? [S/N]"<< endl;
                    cout << result[1] <<endl;
                    string answer;
                    cin >> answer;
                    if(answer=="S") {
                        addTrustCert(config, result[1]);
                        numTent++;
                        connect(config);
                    }else{
                        cout << "Cancelado pelo usuário" << endl;
                        return 7;
                    }
                }else{
                    cout << "Falha" << endl;
                    return 2;
                }
            }else if(result[0] == "CONNECTION_ERROR"){
                cout << "A error occurred trying to connect, see logs" << endl;
                return 3;
            }

        }
    }
    return 1;
}

int closeConnection(){
    string cmd = authorizer+"pkill -f openfortivpn";
    return system(cmd.data());

}

int main(int argc, char * argv[]) {
    string appdir = getexedir();
    confdir = appdir+"/config";
    logdir = appdir+"/log";

    if (system("which openfortivpn > /dev/null 2>&1")) {
        cout << "Install openforticlient first" << endl;
        return 10;
    }
    if (system("which pkexec > /dev/null 2>&1")) {
        authorizer = sudo;
    }

    if(argc > 1){
        if(strcmp(argv[1],"close") == 0){
            return closeConnection();
        }else if(strcmp(argv[1],"config") == 0){
            return addConfig(argv[2]);
        }else if (strcmp(argv[1],"connect")==0){
            return connect(argv[2]);
        }
    }else{
        cout << "usage: "+((string) argv[0])+" (close | config <name> | connect <name>)"<< endl;
    }

    return 0;
}