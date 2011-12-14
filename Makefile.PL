use ExtUtils::MakeMaker;

WriteMakefile(
    AUTHOR	    => 'Greg Banks <gnb@fastmail.fm>',
    NAME	    => 'Devel::Plumber',
    VERSION_FROM    => 'lib/Devel/Plumber.pm',
    EXE_FILES	    => [ 'plumber' ],
);
