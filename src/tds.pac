%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
    %}

analyzer TDS withcontext {
    connection:    TDS_Conn;
    flow:        TDS_Flow;
    };

%include tds-protocol.pac
%include tds-analyzer.pac
