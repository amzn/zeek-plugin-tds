#include "TDS.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::tds;

TDS_Analyzer::TDS_Analyzer(Connection* c): tcp::TCP_ApplicationAnalyzer("TDS", c) {
    interp = new binpac::TDS::TDS_Conn(this);
    had_gap = false;
    }

TDS_Analyzer::~TDS_Analyzer() {
    delete interp;
    }

void TDS_Analyzer::Done() {
    tcp::TCP_ApplicationAnalyzer::Done();
    interp->FlowEOF(true);
    interp->FlowEOF(false);
    }

void TDS_Analyzer::EndpointEOF(bool is_orig) {
    tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
    }

void TDS_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
    assert(TCP());
    //if(TCP()->IsPartial())
    //    return;
    // If only one side had a content gap, we could still try to
    // deliver data to the other side if the script layer can handle this.
    if(had_gap)
        return;

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
        }
    }

void TDS_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    had_gap = true;
    interp->NewGap(orig, len);
    }
