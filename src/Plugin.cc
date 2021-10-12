#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin {
    namespace Zeek_TDS {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_TDS;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::analyzer::Component("TDS", analyzer::tds::TDS_Analyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::TDS";
    config.description = "MS-SQL TDS protocol analyzer";
    return config;
    }
