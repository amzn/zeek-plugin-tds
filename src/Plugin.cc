#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_TDS {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_TDS;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("TDS", ::analyzer::tds::TDS_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::TDS";
    config.description = "MS-SQL TDS protocol analyzer";
    return config;
    }
