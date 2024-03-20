
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek TDS)
    zeek_plugin_cc(src/TDS.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/tds.pac src/tds-analyzer.pac src/tds-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()
