package Apache::ProxyScan;

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

#use Apache::ExtUtils qw(command_table);
#use Apache::src();

# upcoming changes
#my @directives = (
#		  { name   => 'ProxyScanTemporaryDirectory',
#		    errmsg => 'a directory to store downloaded files temporary',
#		    args_how => 'TAKE1',
#		    req_override => 'RSRC_CONF'
#		  },
#		  { name   => 'ProxyScanPredeliverSize',
#		    errmsg => 'minimum size before a file is pre-delivered',
#		    args_how => 'TAKE1',
#		    req_override => 'RSRC_CONF'
#		  },
#		  { name   => 'ProxyScanTrustedMIME',
#		    errmsg => 'a list of trusted mime types',
#		    args_how => 'ITERATE',
#		    req_override => 'RSRC_CONF'
#		  },
#		  { name   => 'ProxyScanTrustedExtension',
#		    errmsg => 'a list of trusted file extensions',
#		    args_how => 'ITERATE',
#		    req_override => 'RSRC_CONF'
#		  },
#		  );
#
#command_table(\@directives);

WriteMakefile(
    'NAME'	   => 'Apache::ProxyScan',
    'VERSION_FROM' => 'ProxyScan.pm',
 #   'INC'          => Apache::src->new->inc,
    'PREREQ_PM'    => {
        'Apache::Constants'     => '0', # or a minimum workable version
        'LWP::UserAgent'	=> '0',
        'File::MMagic'		=> '0',
	'URI::URL'		=> '0',
    }

);
