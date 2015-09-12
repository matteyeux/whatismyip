#!/usr/bin/perl
#Developed by @matteyeux

use LWP::Simple;

$content = get("http://icanhazip.com");

	
print "Your public IP address is $content\n\n";

<>;
