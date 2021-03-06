use 5.010001; # for utf-8, and Time::Piece
use ExtUtils::MakeMaker;

WriteMakefile(
    dist	 => {
	             PREOP	=> 'pod2text XS.pm | tee README >$(DISTVNAME)/README; chmod -R u=rwX,go=rX . ;',
	             COMPRESS	=> 'gzip -9v',
	             SUFFIX	=> '.gz',
	            },
    VERSION_FROM => "XS.pm",
    NAME         => "CBOR::XS",
    PREREQ_PM    => {
       common::sense     => 0,
       Types::Serialiser => 0,
    },
);

