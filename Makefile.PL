use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'	   => 'Apache::ProxyScan',
    'VERSION_FROM' => 'ProxyScan.pm',
    'PREREQ_PM'    => {
        'Apache::Constants'     => '0', # or a minimum workable version
        'LWP::UserAgent'	=> '0',
        'File::Temp'		=> '0',
	'URI::URL'		=> '0',
    }

);
