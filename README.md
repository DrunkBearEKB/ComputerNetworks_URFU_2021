## _1. Tracert_
#### _Usage:_
    python traceroute.py [-h] [-t] [-c] ip

#### _Positional arguments:_
    ip           ip address or domain name

#### _Optional arguments:_
    -h, --help   show this help message and exit
    -t, --time   displays the results of time intervals in three columns
    -c, --clear  clears the console screen before displaying the result


## _2. SNTP_Server_
#### _Usage:_
    python server.py [-h]

#### _Optional arguments:_
    -h, --help   show this help message and exit


## _3. Port_Scanner_
#### _Usage:_
    python port_scanner.py [-h] [--udp] [--check-protocols] host range

#### _Positional arguments:_
    host               host address to check
    range              the interval of ports to check, is set as a start-end, for example, 20-1000

#### _Optional arguments:_
    -h, --help         show this help message and exit
    --udp              check the openness of udp ports
    --check-protocols  check which protocols work on the ports


## _4. Caching_DNS_Server_
#### _Usage:_
    python server.py [-h] [-d] [-i]

#### _Optional arguments:_
    -h, --help       show this help message and exit
    -d, --debug      enable debug on
    -i, --intercept  toggle intercept mode


## _8. VK_API_
#### _Usage:_
    python friends_checker.py [-h] [-t] [-s] id

#### _Positional arguments:_
    id           users_id

#### _Optional arguments:_
    -h, --help   show this help message and exit
    -t, --table  show results as a table
    -s, --save   saves result in file


## _Author_
##### _Ivanenko Grigoriy / Иваненко Григорий_
##### _UrFU KN-204 / УрФУ КН-204_ 
##### _email: ivanenkogrig@yandex.ru_