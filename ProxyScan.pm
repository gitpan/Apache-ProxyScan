package Apache::ProxyScan;

use strict;
use vars qw($VERSION);

use LWP::UserAgent ();
use File::Temp qw/ tempdir /;
use Data::Dumper;
use URI::URL;
use Apache::Constants ':common';

$VERSION = "0.24";

sub handler {
    my($r) = @_;
    return DECLINED unless $r->proxyreq;
    return DECLINED if ($r->method eq "CONNECT");
    $r->handler("perl-script"); #ok, let's do it
    $r->push_handlers(PerlHandler => \&proxy_handler);
    return OK;
}

sub proxy_handler {
    my($r) = @_;
    # get the configuration variables
    my $scanner = $r->dir_config("ProxyScanScanner");
    my $dir = $r->dir_config("ProxyScanTempDir");
    # make a nice filename
    my $file = (URI::URL->new($r->uri))->path;
    $file =~ s/[^A-Z0-9]+/_/igs;
    $file =~ s/^$/file/igs;
 
    # create the request
    my $request = new HTTP::Request $r->method, $r->uri;

    # copy request headers
    my($key,$val);
    my(%headers_in) = $r->headers_in;
    while(($key,$val) = each %headers_in) {
	$request->header($key,$val);
    }

    # transfer request if it's POST
    # try to handle without content length
    if ($r->method eq 'POST') {
       my $len = $r->header_in('Content-length');
       if (defined $len) {
         my $buf;
         $r->read($buf, $len);
         $request->content($buf);
       } else {
	 $request->content(scalar $r->content);
       }
    }

    # download request in unique directory
    my $tmpdir = tempdir(  DIR => "$dir" );
    my $res = (new LWP::UserAgent)->simple_request($request,"$tmpdir/$file");

    # if an error occurs, res->content contains server error
    # we are paraniod so we scan the server message too
    # DNS Errors are reported by LWP::UA as Code 500 with empty content
    if (!$res->is_success) {
	my $fh = Apache::gensym();
        open($fh, ">$tmpdir/$file");
	my $msg = $res->content;
        if (($res->code == 500) && ($msg eq "")) {
          $msg = $res->message;
	}
        print $fh $msg;
        close($fh);
    }

    # try to scan file
    my $fh = Apache::gensym();
    open($fh,"$scanner '$tmpdir/$file' |");
    my @msg=<$fh>;
    close($fh);
    my $scanrc = $?;
    
    # feed reponse back into our request_rec*
    $r->content_type($res->header('Content-type'));
    $r->status($res->code);
    $r->status_line($res->status_line);
    my $table = $r->headers_out;
    $res->scan(sub {
        $table->add(@_);
    });

    # The following return code combinations from scanner
    #  rc  file
    #   0  exists    clean, return file
    #   0  deleted   not allowed, fixed error Message
    #  !0  exists    scan failed, fixed error Message
    #  !0  deleted   infected, return stdout

    if ($scanrc == 0) {
      if (-e "$tmpdir/$file") {
        $r->send_http_header();
        my $fh = Apache::gensym();
        open($fh, "<$tmpdir/$file");
        $r->send_fd($fh);
        close($fh);
      } else {
        if ($res->is_error) {
	  $r->send_http_header();
	  $r->print($res->error_as_HTML);
        } else {
          my $msg=join("\n", @msg);
          generateError(\$r, "Scanner Error", "Scanning ".$r->uri.":\n$msg");
        }
      }
    } else {
      if (-e "$tmpdir/$file") {
        my $msg=join("\n", @msg);
        generateError(\$r, "Scanner Error", "Scanning ".$r->uri.":\n$msg");
      } else {
        $r->header_out("content-length" => undef);
        $r->send_cgi_header(join('', @msg));
      }
    }

    unlink "$tmpdir/$file" if (-e "$tmpdir/$file");
    rmdir "$tmpdir";

    return OK;
}

sub generateError {
    my $r = shift @_;
    my $title = shift @_;
    my $text = shift @_;   
    
    $text =~ s/[^A-Z0-9_\s\n]/sprintf("&#%d;", ord($&))/eigs;
    $text =~ s/\n/<BR>/igs;

    my $msg = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>$title</title>\n</head><body>\n<h1>$title</h1>\n$text\n</body></html>\n";

    $$r->content_type("text/html");
    $$r->header_out("content-length" => length($msg));
    $$r->send_http_header();
    $$r->print("$msg");
      
    return 1;
}



1;

__END__

=head1 NAME

Apache::ProxyScan - proxy module to integrate content scanners

=head1 SYNOPSIS

  # httpd.conf 
  # example for clamav
  PerlTransHandler  Apache::ProxyScan
  PerlSetVar        ProxyScanScanner "/usr/local/bin/clamav.pl"
  PerlSetVar        ProxyScanTempDir /var/cache/virus/dl/
  PerlSetEnv 	    SCAN_TMP 	   /var/cache/virus/av/

=head1 DESCRIPTION

This module provides the integration of any commandline virus scanning tool
into the proxy chain of apache. It works better than cgi solutions because
this module uses libwww-perl as it's web client, feeding the response
back into the Apache API request_rec structure. For this reason there are
no troubles with authentication nor cookie sites.

`PerlHandler' will only be invoked if the request is a proxy request,
otherwise, your normal server configuration will handle the request.
The normal server configuration will also handle the CONNECT requests if
defined for this.

I tested it with clamav, sophos, rav and mcafee.

=head1 PARAMETERS

This module is configured with PerlSetVar and PerlSetEnv.

=head2 ProxyScanScanner

This is the command executed to scan the downloaded file before delivering.
We use standard executables, normally perl.

The only parameter given to the executable is the temporary filename of the 
file to be tested.

The script must return 0 if the file is clean and tested und the file
must not be deleted. 
If the return code ist not 0 and the file still exists, we assume that the
call of the scanner wrapper failed. The file is not deliverd.
If the return code ist not 0 and the file is deleted, then the Handler
returns the standard output of the wrapper script.

=head2 ProxyScanTempDir

This is the directory where LWP::UserAgent downloads the requested files.
Make sure that it provides enough space for you surf load.

  PerlSetVar        ProxyScanTempDir /var/cache/virus/dl/

Often the scanner itself have another place where to store their temporary
files. Make sure that it provides enough space, too. 

=head2 PerlSetEnv

The scripts starting the scan processes try to set the path for the temporary
files created by the scanner itself.

  PerlSetEnv 	    SCAN_TMP 	   /var/cache/virus/av/

=head1 EXAMPLES

I need more example configuration for other scanner products.
If a file is infected, the scanner should delete it.

In Apache-ProxyScan-X.XX/eg/ are wrapper scripts for several virus scanner.
Change


=head1 TODO

I need tests and examples for the integration of other content scanner 
products, free and non free. (Kaspersky, Trendmicro, AntiVir)

=head1 SUPPORT

The latest version of this module can be found at CPAN and at
L<http://trancentral.org/code/Apache::ProxyScan/>. Send questions and
suggestions directly to the author (see below).

=head1 SEE ALSO

mod_perl(3), Apache(3), LWP::UserAgent(3)

=head1 AUTHOR

Oliver Paukstadt <cpan@trancentral.org>

Based on Apache::ProxyPassThrough from Bjoern Hansen and Doug MacEachern

=head1 COPYRIGHT

Copyright (c) 2002-2003 Oliver Paukstadt. All rights reserved.
This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=head1 FORTUNE

DA FORCE COMING DOWN WITH MAYHEM
LOOKING AT MY WATCH TIME 3.A.M.
