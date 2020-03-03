#ifndef ANALYZER_PROTOCOL_TDS_H
#define ANALYZER_PROTOCOL_TDS_H

#include "analyzer/protocol/tcp/TCP.h"
#include "tds_pac.h"

namespace analyzer { 
    namespace tds {
        class TDS_Analyzer : public tcp::TCP_ApplicationAnalyzer {
            public:
                TDS_Analyzer(Connection* conn);
                virtual ~TDS_Analyzer();

                virtual void Done();
                virtual void DeliverStream(int len, const u_char* data, bool orig);
                virtual void Undelivered(uint64_t seq, int len, bool orig);

                virtual void EndpointEOF(bool is_orig);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new TDS_Analyzer(conn);
                    }

            protected:
                binpac::TDS::TDS_Conn* interp;
                bool had_gap;
            };
        } 
    }

#endif
