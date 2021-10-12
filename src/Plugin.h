#ifndef ZEEK_PLUGIN_ZEEK_TDS
#define ZEEK_PLUGIN_ZEEK_TDS

#include <zeek/plugin/Plugin.h>
#include "TDS.h"

namespace plugin {
    namespace Zeek_TDS {
        class Plugin : public zeek::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual zeek::plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
